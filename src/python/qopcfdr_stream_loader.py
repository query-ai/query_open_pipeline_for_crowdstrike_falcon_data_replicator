import logging

logger = logging.getLogger()
logger.setLevel("INFO")

from botocore.config import Config

retryConfig = Config(
    retries={
        "max_attempts": 15,
        "mode": "adaptive"
    }
)

import boto3
from botocore.exceptions import ClientError

sqs = boto3.client("sqs", config=retryConfig)
s3 = boto3.client("s3", config=retryConfig)
sts = boto3.client("sts")

from os import getenv

QOPCFDR_MAPPING_BUCKET = getenv("QOPCFDR_MAPPING_BUCKET")
AWS_REGION = getenv("AWS_DEFAULT_REGION")
AWS_ACCOUNT_ID = str(sts.get_caller_identity()["Account"])

from sys import exit as sysexit
from io import BytesIO
from gzip import GzipFile as gunzip, BadGzipFile
from datetime import datetime
import json

ocsfMappingResp = s3.get_object(
    Bucket=QOPCFDR_MAPPING_BUCKET, Key=f"QFDR_OCSF_Mapping.json"
)
ocsfMappingBody = ocsfMappingResp["Body"].read().decode("utf-8")

QFDR_OCSF_NORMALIZATION = list(json.loads(ocsfMappingBody))
del ocsfMappingResp

classMappingResp = s3.get_object(
    Bucket=QOPCFDR_MAPPING_BUCKET, Key=f"mapped_qfdr_events_to_class.json"
)
classMappingBody = classMappingResp["Body"].read().decode("utf-8")

QFDR_CLASS_EVENT_MAPPING = list(json.loads(classMappingBody))
del classMappingResp

OCSF_HTTP_ACTIVITY_MAPPING = {
    "Connect": 1,
    "Delete": 2,
    "Get": 3,
    "Head": 4,
    "Options": 5,
    "Post": 6,
    "Put": 7,
    "Trace": 8
}

EVENT_CLASS_OCSF_MAPPING = {
    "extApi": f"https://sqs.{AWS_REGION}.amazonaws.com/{AWS_ACCOUNT_ID}/qopcfdr_extapi_http_activity_queue",
    "Process Activity": f"https://sqs.{AWS_REGION}.amazonaws.com/{AWS_ACCOUNT_ID}/qopcfdr_process_activity_queue",
    "Network Activity": f"https://sqs.{AWS_REGION}.amazonaws.com/{AWS_ACCOUNT_ID}/qopcfdr_network_activity_queue",
    "Device Config State": f"https://sqs.{AWS_REGION}.amazonaws.com/{AWS_ACCOUNT_ID}/qopcfdr_device_config_state_queue",
    "HTTP Activity": f"https://sqs.{AWS_REGION}.amazonaws.com/{AWS_ACCOUNT_ID}/qopcfdr_http_activity_queue",
    "File System Activity": f"https://sqs.{AWS_REGION}.amazonaws.com/{AWS_ACCOUNT_ID}/qopcfdr_file_system_activity_queue",
    "DNS Activity": f"https://sqs.{AWS_REGION}.amazonaws.com/{AWS_ACCOUNT_ID}/qopcfdr_dns_activity_queue",
    "Authentication": f"https://sqs.{AWS_REGION}.amazonaws.com/{AWS_ACCOUNT_ID}/qopcfdr_authentication_queue",
    "File Hosting Activity": f"https://sqs.{AWS_REGION}.amazonaws.com/{AWS_ACCOUNT_ID}/qopcfdr_file_hosting_activity_queue",
    "Module Activity": f"https://sqs.{AWS_REGION}.amazonaws.com/{AWS_ACCOUNT_ID}/qopcfdr_module_activity_queue",
    "Application Lifecycle": f"https://sqs.{AWS_REGION}.amazonaws.com/{AWS_ACCOUNT_ID}/qopcfdr_application_lifecycle_queue",
    "Operating System Patch State": f"https://sqs.{AWS_REGION}.amazonaws.com/{AWS_ACCOUNT_ID}/qopcfdr_operating_system_patch_state_queue",
    "Detection Finding": f"https://sqs.{AWS_REGION}.amazonaws.com/{AWS_ACCOUNT_ID}/qopcfdr_detection_finding_queue"
}

def lambdaHandler(event, context):
    for record in event["Records"]:
        payload = json.loads(record["body"])

        bucketName = payload["detail"]["bucket"]["name"]
        keyName = payload["detail"]["object"]["key"]

        logger.info("Processing %s/%s.", bucketName, keyName)

        processObject(bucketName, keyName)

def processObject(bucketName: str, keyName: str):
    """Processes an FDR object based on an event to Lambda"""
    mappedEvents = [x["EventName"] for x in QFDR_OCSF_NORMALIZATION]

    buffer = BytesIO()
    s3.download_fileobj(
        bucketName,
        keyName,
        buffer
    )
    
    buffer.seek(0)

    # This error handling *shouldnt* be needed, typically it's indicative of issues with buffer, such as putting it outside the for loop -_-
    try:
        with gunzip(fileobj=buffer, mode="rb") as gz:
            jsonLines = gz.read().decode("utf-8").splitlines()
    except BadGzipFile as err:
        logger.warning(
            "Error decompressing S3 key %s because: %s.",
            keyName, err
        )
        sysexit(2)
    
    for line in jsonLines:
        jsonLine = json.loads(line)
        try:
            evName = jsonLine["event_simpleName"]
        except KeyError:
            try:
                evName = jsonLine["event_type"]
            except KeyError:
                try:
                    evName = jsonLine["EventType"]
                except KeyError:
                    logger.warning(
                        "Event distinction data is missing from log line stored in S3 Key %s. Log line: %s",
                        keyName, jsonLine
                    )
                    continue

        if evName in mappedEvents:
            ocsfQfdrMapper(
                eventName=evName,
                payload=jsonLine
            )
        else:
            logger.warning("Event name %s is not in mapped events. Please consider opening an Issue or PR providing a mapping for the event and payload: %s.", evName, jsonLine)
            continue

def sendToSqs(className: str, payload: dict):
    """Sends OCSF-normalize dicts to SQS"""
    queueUrl = EVENT_CLASS_OCSF_MAPPING[className]

    try:
        sqs.send_message(
            QueueUrl=queueUrl,
            MessageBody=json.dumps(payload)
        )
    except ClientError as err:
        logger.warning("Error sending records to SQS because: %s", err)

def ocsfQfdrMapper(eventName: str, payload: dict):
    """Takes in an event name and payload and normalizes into OCSF by matching an event to a class-specific parser"""

    # Event_ExternalApiEvent is a special case
    if eventName == "Event_ExternalApiEvent":
        ocsf = externalApiEventNormalizer(eventName, payload)
        className = "extApi"
        logger.info("Sending %s class to SQS", className)
        sendToSqs(className=className, payload=ocsf)
    else:
        for c in QFDR_CLASS_EVENT_MAPPING:
            className = c["ClassName"]
            if eventName in c["MappedFdrEvents"]:
                if className == "Device Config State":
                    ocsf = deviceConfigStateNormalizer(eventName, payload)
                    logger.info("Sending %s class to SQS", className)
                    sendToSqs(className, payload=ocsf)
                elif className == "Process Activity":
                    ocsf = processActivityNormalizer(eventName, payload)
                    logger.info("Sending %s class to SQS", className)
                    sendToSqs(className, payload=ocsf)
                elif className == "Network Activity":
                    ocsf = networkActivityNormalizer(eventName, payload)
                    logger.info("Sending %s class to SQS", className)
                    sendToSqs(className, payload=ocsf)
                elif className == "HTTP Activity":
                    # this has to be handled differently due to a completly different format
                    if eventName == "Event_ExternalApiEvent":
                        continue
                    else:
                        ocsf = httpActivityNormalizer(eventName, payload)
                        logger.info("Sending %s class to SQS", className)
                        sendToSqs(className, payload=ocsf)
                elif className == "File System Activity":
                    ocsf = fileSystemActivityNormalizer(eventName, payload)
                    logger.info("Sending %s class to SQS", className)
                    sendToSqs(className, payload=ocsf)
                elif className == "Module Activity":
                    ocsf = moduleActivityNormalizer(eventName, payload)
                    logger.info("Sending %s class to SQS", className)
                    sendToSqs(className, payload=ocsf)
                elif className == "DNS Activity":
                    ocsf = dnsActivityNormalizer(eventName, payload)
                    logger.info("Sending %s class to SQS", className)
                    sendToSqs(className, payload=ocsf)
                elif className == "Authentication":
                    ocsf = authenticationNormalizer(eventName, payload)
                    logger.info("Sending %s class to SQS", className)
                    sendToSqs(className, payload=ocsf)
                elif className == "Application Lifecycle":
                    ocsf = applicationLifecycleNormalizer(eventName, payload)
                    logger.info("Sending %s class to SQS", className)
                    sendToSqs(className, payload=ocsf)
                elif className == "Operating System Patch State":
                    ocsf = operatingSystemPatchStateeNormalizer(eventName, payload)
                    logger.info("Sending %s class to SQS", className)
                    sendToSqs(className, payload=ocsf)
                elif className == "File Hosting Activity":
                    ocsf = fileHostingActivityNormalizer(eventName, payload)
                    logger.info("Sending %s class to SQS", className)
                    sendToSqs(className, payload=ocsf)
                elif className == "Detection Finding":
                    ocsf = detectionFindingNormalizer(eventName, payload)
                    logger.info("Sending %s class to SQS", className)
                    sendToSqs(className, payload=ocsf)
    
def epochToTimestamp(unixTime: str | int) -> str:
    """Takes in an epochmilliseconds timestamp and converts it to SQL timestamp(3)"""
    try:
        milliDate = datetime.fromtimestamp(float(unixTime))
        timestamp3 = str(milliDate.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3])
    except ValueError:
        milliDate = datetime.fromtimestamp(float(unixTime) / 1000)
        timestamp3 = str(milliDate.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3])
    
    return timestamp3

def commonFdrParser(payload: dict) -> dict:
    """
    Parses common fields in a FDR event and returns them along with a modified payload that removes any key that is not None for purposes of using it in `unmapped`
    
    While using .get() would be better, when converting this to a dict an error is thrown: TypeError: unhashable type: 'list'
    TODO: Unfuck this?
    """

    try:
        message = payload["name"]
        del payload["name"]
    except KeyError:
        message = None
    try:
        agentId = payload["aid"]
        del payload["aid"]
    except KeyError:
        agentId = None
    try:
        computerId = payload["cid"]
        del payload["cid"]
    except KeyError:
        computerId = None
    try:
        timestamp = payload["timestamp"]
        del payload["timestamp"]
    except KeyError:
        # 24 APR 1998 02:07:39 GMT
        timestamp = "893383659000"
    try:
        eventId = payload["id"]
        del payload["id"]
    except KeyError:
        eventId = None
    try:
        agentIp = payload["aip"]
        del payload["aip"]
    except KeyError:
        agentIp = None

    return {
        "name": message,
        "aid": agentId,
        "cid": computerId,
        "timestamp": timestamp,
        "id": eventId,
        "aip": agentIp,
        "unmapped": payload
    }

def externalApiEventNormalizer(eventName: str, payload: dict) -> dict:
    """Normalizes the FDR event 'Event_ExternalApiEvent' into HTTP Activity (4002)"""
    baseEventMapping = dict([x for x in QFDR_OCSF_NORMALIZATION if x["EventName"] == eventName][0])
    # contains HTTP headers and CRWD FDR values of note
    auditKvs = list(payload["AuditKeyValues"])

    requestMethod = [x["ValueString"] for x in auditKvs if x["Key"] == "request_method"]
    if requestMethod:
        httpRequestMethod = str(requestMethod[0])
        activityName = httpRequestMethod.lower().capitalize()
        activityId = int(OCSF_HTTP_ACTIVITY_MAPPING[activityName])
    else:
        httpRequestMethod = None
        activityName = "Unknown"
        activityId = 0

    statusCode = [x["ValueString"] for x in auditKvs if x["Key"] == "status_code"]
    if statusCode:
        httpStatusCode = int(statusCode[0])
        if str(httpStatusCode).startswith(("1","2","3")):
            statusId = 1
            statusName = "Success"
        else:
            statusId = 2
            statusName = "Failure"
    else:
        statusId = 0
        statusName = "Unknown"

    try:
        userAgent = [x["ValueString"] for x in auditKvs if x["Key"] == "user_agent"][0]
    except IndexError:
        userAgent = None

    try:
        length = int([x["ValueString"] for x in auditKvs if x["Key"] == "request_uri_length"][0])
    except IndexError:
        length = None

    try:
        traceId = [x["ValueString"] for x in auditKvs if x["Key"] == "trace_id"][0]
    except IndexError:
        traceId = None

    try:
        requestPath = [x["ValueString"] for x in auditKvs if x["Key"] == "request_path"][0]
    except IndexError:
        requestPath = None

    try:
        acceptHeader = [x["ValueString"] for x in auditKvs if x["Key"] == "request_accept"][0]
    except IndexError:
        acceptHeader = None

    try:
        contentTypeHeader = [x["ValueString"] for x in auditKvs if x["Key"] == "request_content_type"][0]
    except IndexError:
        contentTypeHeader = None

    try:
        apiClientId = [x["ValueString"] for x in auditKvs if x["Key"] == "APIClientID"][0]
    except IndexError:
        apiClientId = None

    userIp = payload["UserIp"] if payload["UserIp"] else None
    aid = payload["AgentIdString"] if payload["AgentIdString"] else None
    cid = payload["cid"] if payload["cid"] else None
    userId = payload["UserId"] if payload["UserId"] else None
    customerId = payload["CustomerIdString"] if payload["CustomerIdString"] else None

    agentList = []
    observables = []
    if userAgent:
        observables.append(
            {
                "name": "http_request.user_agent",
                "type_id": 16,
                "type": "HTTP User-Agent",
                "value": userAgent
            }
        )
    if apiClientId:
       observables.append(
            {
                "name": "connection_info.session.credential_uid",
                "type_id": 10,
                "type": "Resource UID",
                "value": apiClientId
            }
        ) 
    if userIp:
        observables.append(
            {
                "name": "src_endpoint.ip",
                "type_id": 2,
                "type": "IP Address",
                "value": userIp
            }
        )
    if aid:
        observables.append(
            {
                "name": "src_endpoint.agent_list[0].uid",
                "type_id": 10,
                "type": "Resource UID",
                "value": aid
            }
        )
        agentList.append(
            {
                "uid": aid,
                "name": "Crowdstrike Falcon Agent",
                "version": None,
                "type_id": 1,
                "type": "Endpoint Detection and Response",
                "vendor_name": "Crowdstrike"
            }
        )
    else:
        agentList.append(
            {
                "uid": None,
                "name": "Crowdstrike Falcon Agent",
                "version": None,
                "type_id": 1,
                "type": "Endpoint Detection and Response",
                "vendor_name": "Crowdstrike"
            }
        )
    if cid:
        observables.append(
            {
                "name": "src_endpoint.uid",
                "type_id": 10,
                "type": "Resource UID",
                "value": cid
            }
        )
    if userId:
        observables.append(
            {
                "name": "src_endpoint.owner.uid",
                "type_id": 10,
                "type": "Resource UID",
                "value": userId
            }
        )
    if customerId:
        observables.append(
            {
                "name": "src_endpoint.owner.account.uid",
                "type_id": 10,
                "type": "Resource UID",
                "value": customerId
            }
        )

    className = str(baseEventMapping["ClassName"])
    classUid = int(baseEventMapping["ClassUid"])

    ocsf = {
        "activity_name": activityName,
        "activity_id": activityId,
        "category_name": baseEventMapping["CategoryName"],
        "category_uid": baseEventMapping["CategoryId"],
        "class_name": className,
        "class_uid": classUid,
        "severity": baseEventMapping["SeverityName"],
        "severity_id": baseEventMapping["SeverityId"],
        "status": statusName,
        "status_id": statusId,
        "type_name": f"{className}: {activityName}",
        "type_uid": (classUid * 100) + activityId,
        "time": epochToTimestamp(payload["UTCTimestamp"]),
        "message": payload["ExternalApiType"],
        "observables": observables,
        "metadata": {
            "uid": traceId,
            "log_name": eventName,
            "log_provider": "Falcon Data Replicator",
            "version": "1.2.0",
            "profiles": [],
            "product": {
                "lang": "en",
                "name": "Crowdstrike Falcon",
                "vendor_name": "Crowdstrike",
                "url_string": "https://www.crowdstrike.com/resources/data-sheets/falcon-data-replicator/"
            }
        },
        "http_request": {
            "http_method": httpRequestMethod,
            "user_agent": userAgent,
            "length": length,
            "uid": traceId,
            "http_headers": [
                {
                    "name": "Accept",
                    "value": acceptHeader
                },
                {
                    "name": "Content-Type",
                    "value": contentTypeHeader
                },
                {
                    "name": "User-Agent",
                    "value": userAgent
                }
            ],
            "url": {
                "path": requestPath
            }
        },
        "connection_info": {
            "boundary_id": 0,
            "boundary": "Unknown",
            "uid": traceId,
            "direction_id": 2,
            "direction": "Outbound",
            "protocol_ver_id": 0,
            "protocol_ver": "Unknown",
            "protocol_name": "tcp",
            "protocol_num": 17,
            "session": {
                "credential_uid": apiClientId
            }
        },
        "src_endpoint": {
            "ip": userIp,
            "uid": cid,
            "owner": {
                "uid": userId,
                "type_id": 0,
                "type": "Unknown",
                "account": {
                    "uid": customerId,
                    "type_id": 99,
                    "type": "Crowdstrike"
                }
            },
            "agent_list": agentList
        }
    }

    return ocsf

def deviceConfigStateNormalizer(eventName: str, payload: dict) -> dict:
    """Normalizes various FDR events into Device Config State (5002)"""
    baseEventMapping = dict([x for x in QFDR_OCSF_NORMALIZATION if x["EventName"] == eventName][0])

    # Parse common vars in mapped events
    commonParsing = commonFdrParser(payload)
    del payload
    # this is essentially the old payload minus common attributes parsed
    unmapped = dict(commonParsing["unmapped"])
    try:
        configBuild = unmapped["ConfigBuild"]
        del unmapped["ConfigBuild"]
    except KeyError:
        configBuild = None
    try:
        platformType = unmapped["event_platform"]
        del unmapped["event_platform"]
    except KeyError:
        platformType = None

    # Normalize platform type to device.os.type_uid
    if platformType is None:
        deviceOsTypeUid = 0
        deviceOsType = "Unknown"
    elif platformType == "Win":
        deviceOsTypeUid = 100
        deviceOsType = "Windows"
    elif platformType == "Lin":
        deviceOsTypeUid = 200
        deviceOsType = "Linux"
    elif platformType == "Mac":
        deviceOsTypeUid = 300
        deviceOsType = "macOS"
    else:
        deviceOsTypeUid = 99
        deviceOsType = platformType

    # Normalize typical mappings of aid, aip, cid to observables
    observables = []
    aid = commonParsing["aid"]
    cid = commonParsing["cid"]
    aip = commonParsing["aip"]
    
    if aid:
        observables.append(
            {
                "name": "device.agent_list[0].uid",
                "type_id": 10,
                "type": "Resource UID",
                "value": aid
            }
        )
    if cid:
        observables.append(
            {
                "name": "device.uid",
                "type_id": 10,
                "type": "Resource UID",
                "value": cid
            }
        )
    if aip:
        observables.append(
            {
                "name": "device.ip",
                "type_id": 2,
                "type": "IP Address",
                "value": aip
            }
        )

    className = str(baseEventMapping["ClassName"])
    classUid = int(baseEventMapping["ClassUid"])
    activityId = int(baseEventMapping["ActivityId"])
    activityName = str(baseEventMapping["ActivityName"])

    ocsf = {
        "activity_name": activityName,
        "activity_id": activityId,
        "category_name": baseEventMapping["CategoryName"],
        "category_uid": baseEventMapping["CategoryId"],
        "class_name": className,
        "class_uid": classUid,
        "severity": baseEventMapping["SeverityName"],
        "severity_id": baseEventMapping["SeverityId"],
        "status": baseEventMapping["StatusName"],
        "status_id": baseEventMapping["StatusId"],
        "type_name": f"{className}: {activityName}",
        "type_uid": (classUid * 100) + activityId,
        "time": epochToTimestamp(commonParsing["timestamp"]),
        "message": commonParsing["name"],
        "observables": observables,
        "metadata": {
            "uid": commonParsing["id"],
            "log_name": eventName,
            "log_provider": "Falcon Data Replicator",
            "version": "1.2.0",
            "profiles": [],
            "product": {
                "lang": "en",
                "name": "Crowdstrike Falcon",
                "vendor_name": "Crowdstrike",
                "url_string": "https://www.crowdstrike.com/resources/data-sheets/falcon-data-replicator/"
            }
        },
        "device": {
            "ip": aip,
            "uid": cid,
            "os": {
                "type_id": deviceOsTypeUid,
                "type": deviceOsType
            },
            "agent_list": [
                {
                    "uid": aid,
                    "name": "Crowdstrike Falcon Agent",
                    "type_id": 1,
                    "type": "Endpoint Detection and Response",
                    "version": configBuild,
                    "vendor_name": "Crowdstrike"
                }
            ]
        },
        "unmapped": unmapped
    }

    return ocsf

def processActivityNormalizer(eventName: str, payload: dict) -> dict:
    """Normalizes various FDR events into Process Activity (1007)"""
    baseEventMapping = dict([x for x in QFDR_OCSF_NORMALIZATION if x["EventName"] == eventName][0])

    # Parse common vars in mapped events
    commonParsing = commonFdrParser(payload)
    del payload
    # this is essentially the old payload minus common attributes parsed
    unmapped = dict(commonParsing["unmapped"])
    try:
        configBuild = unmapped["ConfigBuild"]
        del unmapped["ConfigBuild"]
    except KeyError:
        configBuild = None
    try:
        platformType = unmapped["event_platform"]
        del unmapped["event_platform"]
    except KeyError:
        platformType = None

    # Normalize platform type to device.os.type_uid
    if platformType is None:
        deviceOsTypeUid = 0
        deviceOsType = "Unknown"
    elif platformType == "Win":
        deviceOsTypeUid = 100
        deviceOsType = "Windows"
    elif platformType == "Lin":
        deviceOsTypeUid = 200
        deviceOsType = "Linux"
    elif platformType == "Mac":
        deviceOsTypeUid = 300
        deviceOsType = "macOS"
    else:
        deviceOsTypeUid = 99
        deviceOsType = platformType

    # OCSF Arrays, used later...
    observables = []
    hashes = []

    # Parse out Process Activity related k:v pairs
    imageFileName = unmapped.get("ImageFileName", None)
    if imageFileName:
        del unmapped["ImageFileName"]
        observables.append(
            {
                "name": "process.file.name",
                "type_id": 7,
                "type": "File Name",
                "value": imageFileName
            }
        )
    
    sha256Hash = unmapped.get("SHA256HashData", None)
    if sha256Hash:
        del unmapped["SHA256HashData"]
        hashes.append(
            {
                "algorithm_id": 3,
                "algorithm": "SHA-256",
                "value": sha256Hash
            }
        )
        observables.append(
            {
                "name": "process.file.hashes[0].value",
                "type_id": 8,
                "type": "Hash",
                "value": sha256Hash
            }
        )
    
    md5Hash = unmapped.get("MD5HashData", None)
    if md5Hash:
        del unmapped["MD5HashData"]
        hashes.append(
            {
                "algorithm_id": 1,
                "algorithm": "MD5",
                "value": md5Hash
            }
        )
        observables.append(
            {
                "name": "process.file.hashes[1].value",
                "type_id": 8,
                "type": "Hash",
                "value": md5Hash
            }
        )
    
    cmdLine = unmapped.get("CommandLine", None)
    if cmdLine:
        del unmapped["CommandLine"]
        observables.append(
            {
                "name": "process.cmd_line",
                "type_id": 13,
                "type": "Command Line",
                "value": cmdLine
            }
        )
    
    rawPid = unmapped.get("RawProcessId", None)
    if rawPid:
        del unmapped["RawProcessId"]
        observables.append(
            {
                "name": "process.pid",
                "type_id": 13,
                "type": "Process ID",
                "value": rawPid
            }
        )
    
    processUid = unmapped.get("SourceProcessId", None)
    if processUid:
        del unmapped["SourceProcessId"]
    
    parentProcessUid = unmapped.get("ParentProcessId", None)
    if parentProcessUid:
        del unmapped["ParentProcessId"]
    
    parentProcessFileName = unmapped.get("ParentBaseFileName", None)
    if not parentProcessFileName:
        parentProcessFileName = unmapped.get("ParentImageFileName", None)
    if parentProcessFileName:
        del unmapped["ParentBaseFileName"]
        observables.append(
            {
                "name": "process.parent_process.file.name",
                "type_id": 7,
                "type": "File Name",
                "value": parentProcessFileName
            }
        )
    
    parentCommandLine = unmapped.get("ParentCommandLine", None)
    if parentCommandLine:
        del unmapped["ParentCommandLine"]
        observables.append(
            {
                "name": "process.parent_process.cmd_line",
                "type_id": 13,
                "type": "Command Line",
                "value": parentCommandLine
            }
        )

    # File in nulls to hashes if there isnt anything there
    if not hashes:
        hashes = [
            {
                "algorithm_id": None,
                "algorithm": None,
                "value": None
            }
        ]

    # Normalize typical mappings of aid, aip, cid to observables
    aid = commonParsing["aid"]
    cid = commonParsing["cid"]
    aip = commonParsing["aip"]
    
    if aid:
        observables.append(
            {
                "name": "device.agent_list[0].uid",
                "type_id": 10,
                "type": "Resource UID",
                "value": aid
            }
        )
    if cid:
        observables.append(
            {
                "name": "device.uid",
                "type_id": 10,
                "type": "Resource UID",
                "value": cid
            }
        )
    if aip:
        observables.append(
            {
                "name": "device.ip",
                "type_id": 2,
                "type": "IP Address",
                "value": aip
            }
        )

    className = str(baseEventMapping["ClassName"])
    classUid = int(baseEventMapping["ClassUid"])
    activityId = int(baseEventMapping["ActivityId"])
    activityName = str(baseEventMapping["ActivityName"])

    ocsf = {
        "activity_name": activityName,
        "activity_id": activityId,
        "category_name": baseEventMapping["CategoryName"],
        "category_uid": baseEventMapping["CategoryId"],
        "class_name": className,
        "class_uid": classUid,
        "severity": baseEventMapping["SeverityName"],
        "severity_id": baseEventMapping["SeverityId"],
        "status": baseEventMapping["StatusName"],
        "status_id": baseEventMapping["StatusId"],
        "type_name": f"{className}: {activityName}",
        "type_uid": (classUid * 100) + activityId,
        "time": epochToTimestamp(commonParsing["timestamp"]),
        "message": commonParsing["name"],
        "observables": observables,
        "metadata": {
            "uid": commonParsing["id"],
            "log_name": eventName,
            "log_provider": "Falcon Data Replicator",
            "version": "1.2.0",
            "profiles": [],
            "product": {
                "lang": "en",
                "name": "Crowdstrike Falcon",
                "vendor_name": "Crowdstrike",
                "url_string": "https://www.crowdstrike.com/resources/data-sheets/falcon-data-replicator/"
            }
        },
        "device": {
            "ip": aip,
            "uid": cid,
            "os": {
                "type_id": deviceOsTypeUid,
                "type": deviceOsType
            },
            "agent_list": [
                {
                    "uid": aid,
                    "name": "Crowdstrike Falcon Agent",
                    "type_id": 1,
                    "type": "Endpoint Detection and Response",
                    "version": configBuild,
                    "vendor_name": "Crowdstrike"
                }
            ]
        },
        "process": {
            "cmd_line": cmdLine,
            "created_time": epochToTimestamp(commonParsing["timestamp"]),
            "pid": rawPid,
            "uid": processUid,
            "file": {
                "name": imageFileName,
                "hashes": hashes
            },
            "parent_process": {
                "cmd_line": parentCommandLine,
                "created_time": epochToTimestamp(commonParsing["timestamp"]),
                "uid": parentProcessUid,
                "file": {
                    "name": parentProcessFileName
                }
            }
        },
        "unmapped": unmapped
    }

    return ocsf

def networkActivityNormalizer(eventName: str, payload: dict) -> dict:
    """Normalizes various FDR events into Network Activity (4001)"""
    baseEventMapping = dict([x for x in QFDR_OCSF_NORMALIZATION if x["EventName"] == eventName][0])

    # Parse common vars in mapped events
    commonParsing = commonFdrParser(payload)
    del payload
    # this is essentially the old payload minus common attributes parsed
    unmapped = dict(commonParsing["unmapped"])
    try:
        configBuild = unmapped["ConfigBuild"]
        del unmapped["ConfigBuild"]
    except KeyError:
        configBuild = None
    try:
        platformType = unmapped["event_platform"]
        del unmapped["event_platform"]
    except KeyError:
        platformType = None

    # Normalize platform type to device.os.type_uid
    if platformType is None:
        deviceOsTypeUid = 0
        deviceOsType = "Unknown"
    elif platformType == "Win":
        deviceOsTypeUid = 100
        deviceOsType = "Windows"
    elif platformType == "Lin":
        deviceOsTypeUid = 200
        deviceOsType = "Linux"
    elif platformType == "Mac":
        deviceOsTypeUid = 300
        deviceOsType = "macOS"
    else:
        deviceOsTypeUid = 99
        deviceOsType = platformType

    # OCSF Arrays, used later...
    observables = []

    # Parse network_activity specific values from various FDR events
    srcPort = unmapped.get("LocalPort", None)
    if srcPort:
        srcPort = int(srcPort)
        del unmapped["LocalPort"]
        observables.append(
            {
                "name": "src_endpoint.port",
                "type_id": 11,
                "type": "Port",
                "value": srcPort
            }
        )

    dstPort = unmapped.get("RemotePort", None)
    if dstPort:
        dstPort = int(dstPort)
        del unmapped["RemotePort"]
        observables.append(
            {
                "name": "dst_endpoint.port",
                "type_id": 11,
                "type": "Port",
                "value": dstPort
            }
        )

    dstIp = unmapped.get("RemoteAddressIP4", None)
    # IPV6 version if IP4 isn't there
    if not dstIp:
        dstIp = unmapped.get("RemoteAddressIP6", None)
        
    if dstIp:
        try:
            del unmapped["RemoteAddressIP4"]
        except KeyError:
            del unmapped["RemoteAddressIP6"]
        observables.append(
            {
                "name": "dst_endpoint.port",
                "type_id": 11,
                "type": "Port",
                "value": dstIp
            }
        )

    localIp = unmapped.get("LocalAddressIP4", None)
    # IPV6 version if IP4 isn't there
    if not localIp:
        localIp = unmapped.get("LocalAddressIP6", None)

    if localIp:
        try:
            del unmapped["LocalAddressIP4"]
        except KeyError:
            del unmapped["LocalAddressIP6"]
        observables.append(
            {
                "name": "src_endpoint.intermediate_ips[0]",
                "type_id": 2,
                "type": "IP Address",
                "value": localIp
            }
        )

    macAddr = unmapped.get("PhysicalAddress", None)
    if macAddr:
        del unmapped["PhysicalAddress"]
        observables.append(
            {
                "name": "src_endpoint.mac",
                "type_id": 3,
                "type": "MAC Address",
                "value": macAddr
            }
        )

    connDirection = unmapped.get("ConnectionDirection", None)
    if connDirection:
        del unmapped["ConnectionDirection"]
        # OUTBOUND = 0, INBOUND = 1, NEITHER = 2, BOTH = 3
        if connDirection == "0":
            directionId = 2
            directionName = "Outbound"
        elif connDirection == "1":
            directionId = 1
            directionName = "Inbound"
        elif connDirection == "2":
            directionId = 99
            directionName = "Neither"
        elif connDirection == "3":
            directionId = 3
            directionName = "Lateral"
        else:
            directionId = 0
            directionName = "Unknown"
    else:
        directionId = 0
        directionName = "Unknown"

    # normalize connection_info
    if "IP4" in commonParsing["name"]:
        protoVerId = 4
        protoVerName = "Internet Protocol version 4 (IPv4)"
    elif "IP6" in commonParsing["name"]:
        protoVerId = 6
        protoVerName = "Internet Protocol version 6 (IPv6)"
    else:
        protoVerId = 0
        protoVerName = "Unknown"
    
    connectionInfo = {
        "direction": directionName,
        "direction_id": directionId,
        "uid": commonParsing["id"],
        "protocol_ver": protoVerName,
        "protocol_ver_id": protoVerId
    }

    # Normalize typical mappings of aid, aip, cid to observables
    aid = commonParsing["aid"]
    cid = commonParsing["cid"]
    aip = commonParsing["aip"]
    
    if aid:
        observables.append(
            {
                "name": "device.agent_list[0].uid",
                "type_id": 10,
                "type": "Resource UID",
                "value": aid
            }
        )
    if cid:
        observables.append(
            {
                "name": "device.uid",
                "type_id": 10,
                "type": "Resource UID",
                "value": cid
            }
        )
    if aip:
        observables.append(
            {
                "name": "device.ip",
                "type_id": 2,
                "type": "IP Address",
                "value": aip
            }
        )

    className = str(baseEventMapping["ClassName"])
    classUid = int(baseEventMapping["ClassUid"])
    activityId = int(baseEventMapping["ActivityId"])
    activityName = str(baseEventMapping["ActivityName"])

    ocsf = {
        "activity_name": activityName,
        "activity_id": activityId,
        "category_name": baseEventMapping["CategoryName"],
        "category_uid": baseEventMapping["CategoryId"],
        "class_name": className,
        "class_uid": classUid,
        "severity": baseEventMapping["SeverityName"],
        "severity_id": baseEventMapping["SeverityId"],
        "status": baseEventMapping["StatusName"],
        "status_id": baseEventMapping["StatusId"],
        "type_name": f"{className}: {activityName}",
        "type_uid": (classUid * 100) + activityId,
        "time": epochToTimestamp(commonParsing["timestamp"]),
        "message": commonParsing["name"],
        "observables": observables,
        "metadata": {
            "uid": commonParsing["id"],
            "log_name": eventName,
            "log_provider": "Falcon Data Replicator",
            "version": "1.2.0",
            "profiles": [],
            "product": {
                "lang": "en",
                "name": "Crowdstrike Falcon",
                "vendor_name": "Crowdstrike",
                "url_string": "https://www.crowdstrike.com/resources/data-sheets/falcon-data-replicator/"
            }
        },
        "connection_info": connectionInfo,
        "src_endpoint": {
            "ip": aip,
            "uid": cid,
            "mac": macAddr,
            "intermediate_ips": [
                localIp
            ],
            "os": {
                "type_id": deviceOsTypeUid,
                "type": deviceOsType
            },
            "agent_list": [
                {
                    "uid": aid,
                    "name": "Crowdstrike Falcon Agent",
                    "type_id": 1,
                    "type": "Endpoint Detection and Response",
                    "version": configBuild,
                    "vendor_name": "Crowdstrike"
                }
            ]
        },
        "dst_endpoint": {
            "ip": dstIp,
            "port": dstPort
        },
        "unmapped": unmapped
    }

    return ocsf

def httpActivityNormalizer(eventName: str, payload: dict) -> dict:
    """Normalizes various FDR events into HTTP Activity (4002)"""
    baseEventMapping = dict([x for x in QFDR_OCSF_NORMALIZATION if x["EventName"] == eventName][0])

    # Parse common vars in mapped events
    commonParsing = commonFdrParser(payload)
    del payload
    # this is essentially the old payload minus common attributes parsed
    unmapped = dict(commonParsing["unmapped"])
    try:
        configBuild = unmapped["ConfigBuild"]
        del unmapped["ConfigBuild"]
    except KeyError:
        configBuild = None
    try:
        platformType = unmapped["event_platform"]
        del unmapped["event_platform"]
    except KeyError:
        platformType = None

    # OCSF Arrays/Objects, used later...
    observables = []

    if eventName == "HttpRequest":
        httpMethod = unmapped.get("HttpMethod", None)
        if httpMethod:
            del unmapped["HttpMethod"]
            # Map Crowdstrike HttpMethod_decimal to OCSF http_activity.activity_name
            if httpMethod == "0":
                activityName = "Unknown"
                httpRequestMethod = None
                activityId = 0
            elif httpMethod == "1":
                activityName = "Get"
                httpRequestMethod = activityName.upper()
                activityId = OCSF_HTTP_ACTIVITY_MAPPING[activityName]
            elif httpMethod == "2":
                activityName = "Head"
                httpRequestMethod = activityName.upper()
                activityId = OCSF_HTTP_ACTIVITY_MAPPING[activityName]
            elif httpMethod == "3":
                activityName = "Post"
                httpRequestMethod = activityName.upper()
                activityId = OCSF_HTTP_ACTIVITY_MAPPING[activityName]
            elif httpMethod == "4":
                activityName = "Put"
                httpRequestMethod = activityName.upper()
                activityId = OCSF_HTTP_ACTIVITY_MAPPING[activityName]
            elif httpMethod == "5":
                activityName = "Delete"
                httpRequestMethod = activityName.upper()
                activityId = OCSF_HTTP_ACTIVITY_MAPPING[activityName]
            elif httpMethod == "6":
                activityName = "Options"
                httpRequestMethod = activityName.upper()
                activityId = OCSF_HTTP_ACTIVITY_MAPPING[activityName]
            elif httpMethod == "7":
                activityName = "Connect"
                httpRequestMethod = activityName.upper()
                activityId = OCSF_HTTP_ACTIVITY_MAPPING[activityName]
            elif httpMethod == "8":
                activityName = "Trace"
                httpRequestMethod = activityName.upper()
                activityId = OCSF_HTTP_ACTIVITY_MAPPING[activityName]
            elif httpMethod == "9":
                activityName = "Patch"
                httpRequestMethod = None
                activityId = 99
            else:
                activityName = "Unknown"
                httpRequestMethod = None
                activityId = 0
        else:
            activityName = "Unknown"
            httpRequestMethod = None
            activityId = 0
        
        # Only FDR "HttpRequest" event will have these...probably...
        httpHost = unmapped.get("HttpHost", None)
        if httpHost:
            del unmapped["HttpHost"]
            observables.append(
                {
                    "name": "http_request.url.hostname",
                    "type_id": 1,
                    "type": "Hostname",
                    "value": httpHost
                }
            )

        httpPath = unmapped.get("HttpPath", None)
        if httpPath:
            del unmapped["HttpPath"]

        httpRequest = {
            "http_method": httpRequestMethod,
            "uid": commonParsing["id"],
            "url": {
                "hostname": httpHost,
                "path": httpPath
            }
        }
    else:
        activityId = int(baseEventMapping["ActivityId"])
        activityName = str(baseEventMapping["ActivityName"])
        httpRequest = {
            "http_method": None,
            "uid": commonParsing["id"],
            "url": {
                "hostname": None,
                "path": None
            }
        }

    # Normalize platform type to device.os.type_uid
    if platformType is None:
        deviceOsTypeUid = 0
        deviceOsType = "Unknown"
    elif platformType == "Win":
        deviceOsTypeUid = 100
        deviceOsType = "Windows"
    elif platformType == "Lin":
        deviceOsTypeUid = 200
        deviceOsType = "Linux"
    elif platformType == "Mac":
        deviceOsTypeUid = 300
        deviceOsType = "macOS"
    else:
        deviceOsTypeUid = 99
        deviceOsType = platformType


    # Normalize HTTP Activity attributes

    # Status Normalization is possible...sometimes
    statusName = baseEventMapping["StatusName"]
    statusId = baseEventMapping["StatusId"]
    httpStatus = unmapped.get("HttpStatus", None)

    if statusName == "Override":
        if httpStatus is not None:
            if str(httpStatus).startswith("4") or str(httpStatus).startswith("5"):
                statusId = 2
                statusName = "Failure"
            else:
                statusId = 1
                statusName = "Success"

    dstIp = unmapped.get("RemoteAddressIP4", None)
    # IPV6 version if IP4 isn't there
    if not dstIp:
        dstIp = unmapped.get("RemoteAddressIP6", None)
        
    if dstIp:
        try:
            del unmapped["RemoteAddressIP4"]
        except KeyError:
            del unmapped["RemoteAddressIP6"]
        observables.append(
            {
                "name": "dst_endpoint.port",
                "type_id": 11,
                "type": "Port",
                "value": dstIp
            }
        )

    dstPort = unmapped.get("RemotePort", None)
    if dstPort:
        dstPort = int(dstPort)
        del unmapped["RemotePort"]
        observables.append(
            {
                "name": "dst_endpoint.port",
                "type_id": 11,
                "type": "Port",
                "value": dstPort
            }
        )

    srcPort = unmapped.get("LocalPort", None)
    if srcPort:
        srcPort = int(srcPort)
        del unmapped["LocalPort"]
        observables.append(
            {
                "name": "src_endpoint.port",
                "type_id": 11,
                "type": "Port",
                "value": srcPort
            }
        )

    fileName = unmapped.get("ImageFileName", None)
    if fileName:
        del unmapped["ImageFileName"]
        observables.append(
            {
                "name": "file.name",
                "type_id": 7,
                "type": "File Name",
                "value": fileName
            }
        )

    cmdLine = unmapped.get("CommandLine", None)
    if cmdLine:
        del unmapped["CommandLine"]
        observables.append(
            {
                "name": "actor.process.cmd_line",
                "type_id": 13,
                "type": "Command Line",
                "value": cmdLine
            }
        )

    ja3Hash = unmapped.get("Ja3Hash", None)
    if ja3Hash:
        tlsVersion = unmapped.get("TlsVersion", None)
        del unmapped["TlsVersion"]
        del unmapped["Ja3Hash"]
        observables.append(
            {
                "name": "tls.ja3_hash.value",
                "type_id": 8,
                "type": "Hash",
                "value": ja3Hash
            }
        )
        tls = {
            "version": f"1.{tlsVersion}",
            "ja3_hash": {
                "algorithm": "ja3",
                "algorithm_id": 99,
                "value": ja3Hash
            }
        }
    else:
        tls = {
            "version": None,
            "ja3_hash": {
                "algorithm": None,
                "algorithm_id": None,
                "value": None
            }
        }

    domainName = unmapped.get("DomainName", None)
    if domainName:
        del unmapped["DomainName"]
        observables.append(
            {
                "name": "dst_endpoint.domain",
                "type_id": 1,
                "type": "Hostname",
                "value": domainName
            }
        )
    
    # Normalize typical mappings of aid, aip, cid to observables
    aid = commonParsing["aid"]
    cid = commonParsing["cid"]
    aip = commonParsing["aip"]

    if aid:
        observables.append(
            {
                "name": "device.agent_list[0].uid",
                "type_id": 10,
                "type": "Resource UID",
                "value": aid
            }
        )
    if cid:
        observables.append(
            {
                "name": "device.uid",
                "type_id": 10,
                "type": "Resource UID",
                "value": cid
            }
        )
    if aip:
        observables.append(
            {
                "name": "device.ip",
                "type_id": 2,
                "type": "IP Address",
                "value": aip
            }
        )

    className = str(baseEventMapping["ClassName"])
    classUid = int(baseEventMapping["ClassUid"])

    ocsf = {
        "activity_name": activityName,
        "activity_id": activityId,
        "category_name": baseEventMapping["CategoryName"],
        "category_uid": baseEventMapping["CategoryId"],
        "class_name": className,
        "class_uid": classUid,
        "severity": baseEventMapping["SeverityName"],
        "severity_id": baseEventMapping["SeverityId"],
        "status": statusName,
        "status_id": statusId,
        "status_code": httpStatus,
        "type_name": f"{className}: {activityName}",
        "type_uid": (classUid * 100) + activityId,
        "time": epochToTimestamp(commonParsing["timestamp"]),
        "message": commonParsing["name"],
        "observables": observables,
        "metadata": {
            "uid": commonParsing["id"],
            "log_name": eventName,
            "log_provider": "Falcon Data Replicator",
            "version": "1.2.0",
            "profiles": ["host"],
            "product": {
                "lang": "en",
                "name": "Crowdstrike Falcon",
                "vendor_name": "Crowdstrike",
                "url_string": "https://www.crowdstrike.com/resources/data-sheets/falcon-data-replicator/"
            }
        },
        "actor": {
            "process": {
                "cmd_line": cmdLine
            }
        },
        "file": {
            "name": fileName
        },
        "src_endpoint": {
            "ip": aip,
            "uid": cid,
            "port": srcPort,
            "os": {
                "type_id": deviceOsTypeUid,
                "type": deviceOsType
            },
            "agent_list": [
                {
                    "uid": aid,
                    "name": "Crowdstrike Falcon Agent",
                    "type_id": 1,
                    "type": "Endpoint Detection and Response",
                    "version": configBuild,
                    "vendor_name": "Crowdstrike"
                }
            ]
        },
        "dst_endpoint": {
            "ip": dstIp,
            "port": dstPort,
            "domain": domainName
        },
        "http_request": httpRequest,
        "tls": tls,
        "unmapped": unmapped
    }

    return ocsf

def fileSystemActivityNormalizer(eventName: str, payload: dict) -> dict:
    """Normalizes various FDR events into File System Activity (1001)"""
    baseEventMapping = dict([x for x in QFDR_OCSF_NORMALIZATION if x["EventName"] == eventName][0])

    # Parse common vars in mapped events
    commonParsing = commonFdrParser(payload)
    del payload
    # this is essentially the old payload minus common attributes parsed
    unmapped = dict(commonParsing["unmapped"])
    try:
        configBuild = unmapped["ConfigBuild"]
        del unmapped["ConfigBuild"]
    except KeyError:
        configBuild = None
    try:
        platformType = unmapped["event_platform"]
        del unmapped["event_platform"]
    except KeyError:
        platformType = None

    # OCSF Arrays/Objects, used later...
    observables = []

    # Normalize platform type to device.os.type_uid
    if platformType is None:
        deviceOsTypeUid = 0
        deviceOsType = "Unknown"
    elif platformType == "Win":
        deviceOsTypeUid = 100
        deviceOsType = "Windows"
    elif platformType == "Lin":
        deviceOsTypeUid = 200
        deviceOsType = "Linux"
    elif platformType == "Mac":
        deviceOsTypeUid = 300
        deviceOsType = "macOS"
    else:
        deviceOsTypeUid = 99
        deviceOsType = platformType

    # Parse File System Activity attributes
    fileName = unmapped.get("TargetFileName", None)
    if not fileName:
        fileName = unmapped.get("ScriptContentName", None)
    if fileName:
        try:
            del unmapped["TargetFileName"]
        except KeyError:
            del unmapped["ScriptContentName"]

        observables.append(
            {
                "name": "file.name",
                "type_id": 7,
                "type": "File Name",
                "value": fileName
            }
        )

    filePath = unmapped.get("TargetDirectoryName", None)
    if filePath:
        del unmapped["TargetDirectoryName"]
        fileTypeId = 2
        fileTypeName = "Folder"
    else:
        fileTypeId = 1
        fileTypeName = "Regular File"

    fileUid = unmapped.get("FileIdentifier", None)
    if fileUid:
        del unmapped["FileIdentifier"]

    fileCreator = unmapped.get("UserName", None)
    if fileCreator:
        del unmapped["UserName"]
        observables.append(
            {
                "name": "file.creator.name",
                "type_id": 4,
                "type": "User Name",
                "value": fileCreator
            }
        )

    sha256Hash = unmapped.get("SHA256HashData", None)
    if not sha256Hash:
        sha256Hash = unmapped.get("ContentSHA256HashData", None)
    if sha256Hash:
        try:
            del unmapped["SHA256HashData"]
        except KeyError:
            del unmapped["ContentSHA256HashData"]
        observables.append(
            {
                "name": "file.hashes[0].value",
                "type_id": 8,
                "type": "Hash",
                "value": sha256Hash
            }
        )
        hashes = [
            {
                "algorithm_id": 3,
                "algorithm": "SHA-256",
                "value": sha256Hash
            }
        ]
    else:
        hashes = [
            {
                "algorithm_id": None,
                "algorithm": None,
                "value": None
            }
        ]

    # Normalize typical mappings of aid, aip, cid to observables
    aid = commonParsing["aid"]
    cid = commonParsing["cid"]
    aip = commonParsing["aip"]

    if aid:
        observables.append(
            {
                "name": "device.agent_list[0].uid",
                "type_id": 10,
                "type": "Resource UID",
                "value": aid
            }
        )
    if cid:
        observables.append(
            {
                "name": "device.uid",
                "type_id": 10,
                "type": "Resource UID",
                "value": cid
            }
        )
    if aip:
        observables.append(
            {
                "name": "device.ip",
                "type_id": 2,
                "type": "IP Address",
                "value": aip
            }
        )

    className = str(baseEventMapping["ClassName"])
    classUid = int(baseEventMapping["ClassUid"])
    activityId = int(baseEventMapping["ActivityId"])
    activityName = str(baseEventMapping["ActivityName"])

    ocsf = {
        "activity_name": activityName,
        "activity_id": activityId,
        "category_name": baseEventMapping["CategoryName"],
        "category_uid": baseEventMapping["CategoryId"],
        "class_name": className,
        "class_uid": classUid,
        "severity": baseEventMapping["SeverityName"],
        "severity_id": baseEventMapping["SeverityId"],
        "status": baseEventMapping["StatusName"],
        "status_id": baseEventMapping["StatusId"],
        "type_name": f"{className}: {activityName}",
        "type_uid": (classUid * 100) + activityId,
        "time": epochToTimestamp(commonParsing["timestamp"]),
        "message": commonParsing["name"],
        "observables": observables,
        "metadata": {
            "uid": commonParsing["id"],
            "log_name": eventName,
            "log_provider": "Falcon Data Replicator",
            "version": "1.2.0",
            "profiles": [],
            "product": {
                "lang": "en",
                "name": "Crowdstrike Falcon",
                "vendor_name": "Crowdstrike",
                "url_string": "https://www.crowdstrike.com/resources/data-sheets/falcon-data-replicator/"
            }
        },
        "device": {
            "ip": aip,
            "uid": cid,
            "os": {
                "type_id": deviceOsTypeUid,
                "type": deviceOsType
            },
            "agent_list": [
                {
                    "uid": aid,
                    "name": "Crowdstrike Falcon Agent",
                    "type_id": 1,
                    "type": "Endpoint Detection and Response",
                    "version": configBuild,
                    "vendor_name": "Crowdstrike"
                }
            ]
        },
        "file": {
            "name": fileName,
            "uid": fileUid,
            "path": filePath,
            "type_id": fileTypeId,
            "type": fileTypeName,
            "confidentiality_id": 0,
            "confidentiality": "Unknown",
            "creator": {
                "name": fileCreator
            },
            "hashes": hashes
        },
        "unmapped": unmapped
    }

    return ocsf

def moduleActivityNormalizer(eventName: str, payload: dict) -> dict:
    """Normalizes various FDR events into Module Activity (1005)"""
    baseEventMapping = dict([x for x in QFDR_OCSF_NORMALIZATION if x["EventName"] == eventName][0])

    # Parse common vars in mapped events
    commonParsing = commonFdrParser(payload)
    del payload
    # this is essentially the old payload minus common attributes parsed
    unmapped = dict(commonParsing["unmapped"])
    try:
        configBuild = unmapped["ConfigBuild"]
        del unmapped["ConfigBuild"]
    except KeyError:
        configBuild = None
    try:
        platformType = unmapped["event_platform"]
        del unmapped["event_platform"]
    except KeyError:
        platformType = None

    # OCSF Arrays/Objects, used later...
    observables = []
    hashes = []

    # Normalize platform type to device.os.type_uid
    if platformType is None:
        deviceOsTypeUid = 0
        deviceOsType = "Unknown"
    elif platformType == "Win":
        deviceOsTypeUid = 100
        deviceOsType = "Windows"
    elif platformType == "Lin":
        deviceOsTypeUid = 200
        deviceOsType = "Linux"
    elif platformType == "Mac":
        deviceOsTypeUid = 300
        deviceOsType = "macOS"
    else:
        deviceOsTypeUid = 99
        deviceOsType = platformType

    # Pull out Module Acitivy attributes
    moduleName = unmapped.get("BundleID")
    if not moduleName:
        moduleName = unmapped.get("IOServicePath")
    if moduleName:
        try:
            del unmapped["BundleID"]
        except KeyError:
            del unmapped["IOServicePath"]
        
        moduleLoadTypeId = 1
        moduleLoadType = "Standard"
    else:
        moduleLoadTypeId = 0
        moduleLoadType = "Unknown"

    fileName = unmapped.get("ImageFileName")
    if fileName:
        del unmapped["ImageFileName"]
        observables.append(
            {
                "name": "module.file.name",
                "type_id": 7,
                "type": "File Name",
                "value": fileName
            }
        )

    sha256Hash = unmapped.get("SHA256HashData", None)
    if sha256Hash:
        del unmapped["SHA256HashData"]
        observables.append(
            {
                "name": "file.hashes[0].value",
                "type_id": 8,
                "type": "Hash",
                "value": sha256Hash
            }
        )
        hashes.append(
            {
                "algorithm_id": 3,
                "algorithm": "SHA-256",
                "value": sha256Hash
            }
        )

    sha1Hash = unmapped.get("SHA1HashData", None)
    if sha1Hash:
        del unmapped["SHA1HashData"]
        observables.append(
            {
                "name": "file.hashes[1].value",
                "type_id": 8,
                "type": "Hash",
                "value": sha1Hash
            }
        )
        hashes.append(
            {
                "algorithm_id": 2,
                "algorithm": "SHA-1",
                "value": sha1Hash
            }
        )
    
    md5Hash = unmapped.get("MD5HashData", None)
    if md5Hash:
        del unmapped["MD5HashData"]
        observables.append(
            {
                "name": "file.hashes[2].value",
                "type_id": 8,
                "type": "Hash",
                "value": md5Hash
            }
        )
        hashes.append(
            {
                "algorithm_id": 1,
                "algorithm": "MD5",
                "value": md5Hash
            }
        )

    # Null out hashes if it lacks entries
    if not hashes:
        hashes = [
            {
                "algorithm_id": None,
                "algorithm": None,
                "value": None
            }
        ]

    # Normalize typical mappings of aid, aip, cid to observables
    aid = commonParsing["aid"]
    cid = commonParsing["cid"]
    aip = commonParsing["aip"]

    if aid:
        observables.append(
            {
                "name": "device.agent_list[0].uid",
                "type_id": 10,
                "type": "Resource UID",
                "value": aid
            }
        )
    if cid:
        observables.append(
            {
                "name": "device.uid",
                "type_id": 10,
                "type": "Resource UID",
                "value": cid
            }
        )
    if aip:
        observables.append(
            {
                "name": "device.ip",
                "type_id": 2,
                "type": "IP Address",
                "value": aip
            }
        )

    className = str(baseEventMapping["ClassName"])
    classUid = int(baseEventMapping["ClassUid"])
    activityId = int(baseEventMapping["ActivityId"])
    activityName = str(baseEventMapping["ActivityName"])

    ocsf = {
        "activity_name": activityName,
        "activity_id": activityId,
        "category_name": baseEventMapping["CategoryName"],
        "category_uid": baseEventMapping["CategoryId"],
        "class_name": className,
        "class_uid": classUid,
        "severity": baseEventMapping["SeverityName"],
        "severity_id": baseEventMapping["SeverityId"],
        "status": baseEventMapping["StatusName"],
        "status_id": baseEventMapping["StatusId"],
        "type_name": f"{className}: {activityName}",
        "type_uid": (classUid * 100) + activityId,
        "time": epochToTimestamp(commonParsing["timestamp"]),
        "message": commonParsing["name"],
        "observables": observables,
        "metadata": {
            "uid": commonParsing["id"],
            "log_name": eventName,
            "log_provider": "Falcon Data Replicator",
            "version": "1.2.0",
            "profiles": [],
            "product": {
                "lang": "en",
                "name": "Crowdstrike Falcon",
                "vendor_name": "Crowdstrike",
                "url_string": "https://www.crowdstrike.com/resources/data-sheets/falcon-data-replicator/"
            }
        },
        "device": {
            "ip": aip,
            "uid": cid,
            "os": {
                "type_id": deviceOsTypeUid,
                "type": deviceOsType
            },
            "agent_list": [
                {
                    "uid": aid,
                    "name": "Crowdstrike Falcon Agent",
                    "type_id": 1,
                    "type": "Endpoint Detection and Response",
                    "version": configBuild,
                    "vendor_name": "Crowdstrike"
                }
            ]
        },
        "module": {
            "function_name": moduleName,
            "load_type_id": moduleLoadTypeId,
            "load_type": moduleLoadType,
            "file": {
                "name": fileName,
                "hashes": hashes
            }
        },
        "unmapped": unmapped
    }

    return ocsf

def dnsActivityNormalizer(eventName: str, payload: dict) -> dict:
    """Normalizes various FDR events into DNS Activity (4003)"""
    baseEventMapping = dict([x for x in QFDR_OCSF_NORMALIZATION if x["EventName"] == eventName][0])

    # Parse common vars in mapped events
    commonParsing = commonFdrParser(payload)
    del payload
    # this is essentially the old payload minus common attributes parsed
    unmapped = dict(commonParsing["unmapped"])
    try:
        configBuild = unmapped["ConfigBuild"]
        del unmapped["ConfigBuild"]
    except KeyError:
        configBuild = None
    try:
        platformType = unmapped["event_platform"]
        del unmapped["event_platform"]
    except KeyError:
        platformType = None

    # Normalize platform type to device.os.type_uid
    if platformType is None:
        deviceOsTypeUid = 0
        deviceOsType = "Unknown"
    elif platformType == "Win":
        deviceOsTypeUid = 100
        deviceOsType = "Windows"
    elif platformType == "Lin":
        deviceOsTypeUid = 200
        deviceOsType = "Linux"
    elif platformType == "Mac":
        deviceOsTypeUid = 300
        deviceOsType = "macOS"
    else:
        deviceOsTypeUid = 99
        deviceOsType = platformType

    # OCSF Arrays, used later...
    observables = []

    # Parse network_activity specific values from various FDR events
    domainName = unmapped.get("DomainName", None)
    if domainName:
        del unmapped["DomainName"]
        observables.append(
            {
                "name": "query.hostname",
                "type_id": 1,
                "type": "Hostname",
                "value": domainName
            }
        )

    fileName = unmapped.get("ContextBaseFileName", None)
    if fileName:
        observables.append(
            {
                "name": "unmapped.ContextBaseFileName",
                "type_id": 7,
                "type": "File Name",
                "value": fileName
            }
        )

    # Normalize typical mappings of aid, aip, cid to observables
    aid = commonParsing["aid"]
    cid = commonParsing["cid"]
    aip = commonParsing["aip"]
    
    if aid:
        observables.append(
            {
                "name": "device.agent_list[0].uid",
                "type_id": 10,
                "type": "Resource UID",
                "value": aid
            }
        )
    if cid:
        observables.append(
            {
                "name": "device.uid",
                "type_id": 10,
                "type": "Resource UID",
                "value": cid
            }
        )
    if aip:
        observables.append(
            {
                "name": "device.ip",
                "type_id": 2,
                "type": "IP Address",
                "value": aip
            }
        )

    className = str(baseEventMapping["ClassName"])
    classUid = int(baseEventMapping["ClassUid"])
    activityId = int(baseEventMapping["ActivityId"])
    activityName = str(baseEventMapping["ActivityName"])

    ocsf = {
        "activity_name": activityName,
        "activity_id": activityId,
        "category_name": baseEventMapping["CategoryName"],
        "category_uid": baseEventMapping["CategoryId"],
        "class_name": className,
        "class_uid": classUid,
        "severity": baseEventMapping["SeverityName"],
        "severity_id": baseEventMapping["SeverityId"],
        "status": baseEventMapping["StatusName"],
        "status_id": baseEventMapping["StatusId"],
        "type_name": f"{className}: {activityName}",
        "type_uid": (classUid * 100) + activityId,
        "time": epochToTimestamp(commonParsing["timestamp"]),
        "message": commonParsing["name"],
        "observables": observables,
        "metadata": {
            "uid": commonParsing["id"],
            "log_name": eventName,
            "log_provider": "Falcon Data Replicator",
            "version": "1.2.0",
            "profiles": [],
            "product": {
                "lang": "en",
                "name": "Crowdstrike Falcon",
                "vendor_name": "Crowdstrike",
                "url_string": "https://www.crowdstrike.com/resources/data-sheets/falcon-data-replicator/"
            }
        },
        "src_endpoint": {
            "ip": aip,
            "uid": cid,
            "os": {
                "type_id": deviceOsTypeUid,
                "type": deviceOsType
            },
            "agent_list": [
                {
                    "uid": aid,
                    "name": "Crowdstrike Falcon Agent",
                    "type_id": 1,
                    "type": "Endpoint Detection and Response",
                    "version": configBuild,
                    "vendor_name": "Crowdstrike"
                }
            ]
        },
        "query": {
            "opcode": "Query",
            "opcode_id": 0,
            "hostname": domainName
        },
        "rcode_id": 0,
        "rcode": "NoError",
        "unmapped": unmapped
    }

    return ocsf

def authenticationNormalizer(eventName: str, payload: dict) -> dict:
    """Normalizes various FDR events into Authentication (3002)"""
    baseEventMapping = dict([x for x in QFDR_OCSF_NORMALIZATION if x["EventName"] == eventName][0])

    # Parse common vars in mapped events
    commonParsing = commonFdrParser(payload)
    del payload
    # this is essentially the old payload minus common attributes parsed
    unmapped = dict(commonParsing["unmapped"])
    try:
        configBuild = unmapped["ConfigBuild"]
        del unmapped["ConfigBuild"]
    except KeyError:
        configBuild = None
    try:
        platformType = unmapped["event_platform"]
        del unmapped["event_platform"]
    except KeyError:
        platformType = None

    # Normalize platform type to device.os.type_uid
    if platformType is None:
        deviceOsTypeUid = 0
        deviceOsType = "Unknown"
    elif platformType == "Win":
        deviceOsTypeUid = 100
        deviceOsType = "Windows"
    elif platformType == "Lin":
        deviceOsTypeUid = 200
        deviceOsType = "Linux"
    elif platformType == "Mac":
        deviceOsTypeUid = 300
        deviceOsType = "macOS"
    else:
        deviceOsTypeUid = 99
        deviceOsType = platformType

    # OCSF Arrays, used later...
    observables = []

    # Parse authentication specific values from various FDR events
    userName = unmapped.get("UserName", None)
    if userName:
        del unmapped["UserName"]
        observables.append(
            {
                "name": "user.name",
                "type_id": 4,
                "type": "User Name",
                "value": userName
            }
        )

    userPrincipal = unmapped.get("UserPrincipal", None)
    if userPrincipal:
        del unmapped["UserPrincipal"]
        observables.append(
            {
                "name": "user.uid",
                "type_id": 10,
                "type": "Resource UID",
                "value": userPrincipal
            }
        )

    userSid = unmapped.get("UserSid", None)
    if userSid:
        del unmapped["UserSid"]
        observables.append(
            {
                "name": "user.uid_alt",
                "type_id": 10,
                "type": "Resource UID",
                "value": userSid
            }
        )

    authUid = unmapped.get("AuthenticationId", None)
    if authUid:
        del unmapped["AuthenticationId"]

    authUuid = unmapped.get("AuthenticationUuid", None)
    if authUuid:
        del unmapped["AuthenticationUuid"]

    authMac = unmapped.get("AuthenticationIdMac", None)
    if authMac:
        del unmapped["AuthenticationIdMac"]

    logonType = unmapped.get("LogonType", None)
    if logonType:
        if logonType == "2":
            logonTypeUid = 2
            logonTypeName = "Interactive"
        elif logonType == "3":
            logonTypeUid = 3
            logonTypeName = "Network"
        elif logonType == "4":
            logonTypeUid = 4
            logonTypeName = "Batch"
        elif logonType == "5":
            logonTypeUid = 5
            logonTypeName = "OS Service"
        elif logonType == "7":
            logonTypeUid = 7
            logonTypeName = "Unlock"
        elif logonType == "8":
            logonTypeUid = 8
            logonTypeName = "Network Cleartext"
        elif logonType == "9":
            logonTypeUid = 9
            logonTypeName = "New Credentials"
        elif logonType == "10":
            logonTypeUid = 10
            logonTypeName = "Remote Interactive"
        elif logonType == "11":
            logonTypeUid = 11
            logonTypeName = "Cached Interactive"
        elif logonType == "12":
            logonTypeUid = 12
            logonTypeName = "Cached Remote Interactive"
        elif logonType == "13":
            logonTypeUid = 13
            logonTypeName = "Cached Unlock"
        else:
            logonTypeUid = 0
            logonTypeName = "Unknown"
    else:
        logonTypeUid = 0
        logonTypeName = "Unknown"

    processId = unmapped.get("RawProcessId", None)
    if processId:
        del unmapped["RawProcessId"]
        observables.append(
            {
                "name": "logon_process.pid",
                "type_id": 15,
                "type": "Process ID",
                "value": processId
            }
        )

    userIsAdmin = unmapped.get("UserIsAdmin", None)
    if userIsAdmin:
        del unmapped["UserIsAdmin"]
        if userIsAdmin == "1":
            userTypeId = 2
            userTypeName = "Admin"
        else:
            userTypeId = 1
            userTypeName = "User"
    else:
        userTypeId = 0
        userTypeName = "Unknown"
    
    # Normalize typical mappings of aid, aip, cid to observables
    aid = commonParsing["aid"]
    cid = commonParsing["cid"]
    aip = commonParsing["aip"]
    
    if aid:
        observables.append(
            {
                "name": "device.agent_list[0].uid",
                "type_id": 10,
                "type": "Resource UID",
                "value": aid
            }
        )
    if cid:
        observables.append(
            {
                "name": "device.uid",
                "type_id": 10,
                "type": "Resource UID",
                "value": cid
            }
        )
    if aip:
        observables.append(
            {
                "name": "device.ip",
                "type_id": 2,
                "type": "IP Address",
                "value": aip
            }
        )

    className = str(baseEventMapping["ClassName"])
    classUid = int(baseEventMapping["ClassUid"])
    activityId = int(baseEventMapping["ActivityId"])
    activityName = str(baseEventMapping["ActivityName"])

    ocsf = {
        "activity_name": activityName,
        "activity_id": activityId,
        "category_name": baseEventMapping["CategoryName"],
        "category_uid": baseEventMapping["CategoryId"],
        "class_name": className,
        "class_uid": classUid,
        "severity": baseEventMapping["SeverityName"],
        "severity_id": baseEventMapping["SeverityId"],
        "status": baseEventMapping["StatusName"],
        "status_id": baseEventMapping["StatusId"],
        "type_name": f"{className}: {activityName}",
        "type_uid": (classUid * 100) + activityId,
        "time": epochToTimestamp(commonParsing["timestamp"]),
        "message": commonParsing["name"],
        "observables": observables,
        "metadata": {
            "uid": commonParsing["id"],
            "log_name": eventName,
            "log_provider": "Falcon Data Replicator",
            "version": "1.2.0",
            "profiles": [],
            "product": {
                "lang": "en",
                "name": "Crowdstrike Falcon",
                "vendor_name": "Crowdstrike",
                "url_string": "https://www.crowdstrike.com/resources/data-sheets/falcon-data-replicator/"
            }
        },
        "src_endpoint": {
            "ip": aip,
            "uid": cid,
            "os": {
                "type_id": deviceOsTypeUid,
                "type": deviceOsType
            },
            "agent_list": [
                {
                    "uid": aid,
                    "name": "Crowdstrike Falcon Agent",
                    "type_id": 1,
                    "type": "Endpoint Detection and Response",
                    "version": configBuild,
                    "vendor_name": "Crowdstrike"
                }
            ]
        },
        "logon_process": {
            "pid": processId
        },
        "user": {
            "name": userName,
            "uid": userPrincipal,
            "uid_alt": userSid,
            "type": userTypeName,
            "type_id": userTypeId
        },
        "session": {
            "uid": authUid,
            "uuid": authUuid,
            "uid_alt": authMac
        },
        "logon_type": logonTypeName,
        "logon_type_id": logonTypeUid,
        "unmapped": unmapped
    }

    return ocsf

def applicationLifecycleNormalizer(eventName: str, payload: dict) -> dict:
    """Normalizes various FDR events into Application Lifecycle (6002)"""
    baseEventMapping = dict([x for x in QFDR_OCSF_NORMALIZATION if x["EventName"] == eventName][0])

    # Parse common vars in mapped events
    commonParsing = commonFdrParser(payload)
    del payload
    # this is essentially the old payload minus common attributes parsed
    unmapped = dict(commonParsing["unmapped"])
    try:
        configBuild = unmapped["ConfigBuild"]
        del unmapped["ConfigBuild"]
    except KeyError:
        configBuild = None
    try:
        platformType = unmapped["event_platform"]
        del unmapped["event_platform"]
    except KeyError:
        platformType = None

    # Normalize platform type to device.os.type_uid
    if platformType is None:
        deviceOsTypeUid = 0
        deviceOsType = "Unknown"
    elif platformType == "Win":
        deviceOsTypeUid = 100
        deviceOsType = "Windows"
    elif platformType == "Lin":
        deviceOsTypeUid = 200
        deviceOsType = "Linux"
    elif platformType == "Mac":
        deviceOsTypeUid = 300
        deviceOsType = "macOS"
    else:
        deviceOsTypeUid = 99
        deviceOsType = platformType

    # OCSF Arrays, used later...
    observables = []

    # Parse application_actiivty specific values from various FDR events
    statusFlag = unmapped.get("UpdateFlag")
    if statusFlag:
        del unmapped["UpdateFlag"]

        if statusFlag == "0":
            activityId = 99
            activityName = "UPDATE_INVALID"
            statusId = 2
            statusName = "Failure"
        elif statusFlag == "1":
            activityId = 99
            activityName = "UPDATE_ENUMERATION"
            statusId = 1
            statusName = "Success"
        elif statusFlag == "2":
            activityId = 2
            activityName = "Remove"
            statusId = 1
            statusName = "Success"
        elif statusFlag == "3":
            activityId = 1
            activityName = "Install"
            statusId = 1
            statusName = "Success"
        elif statusFlag == "4":
            activityId = 99
            activityName = "UPDATE_OBSOLETE"
            statusId = 2
            statusName = "Failure"
        elif statusFlag == "5":
            activityId = 99
            activityName = "UPDATE_REVISED"
            statusId = 1
            statusName = "Success"
        else:
            activityId = 99
            activityName = "Other"
            statusId = 99
            statusName = "Other"
    else:
        activityId = 0
        activityName = "Unknown"
        statusId = 0
        statusName = "Unknown"
    
    appName = unmapped.get("AppName")
    if appName:
        del unmapped["AppName"]

    appSource = unmapped.get("AppSource")
    if appSource:
        del unmapped["AppSource"]

    appVendor = unmapped.get("AppVendor")
    if appVendor:
        del unmapped["AppVendor"]

    appVersion = unmapped.get("AppVersion")
    if appVersion:
        del unmapped["AppVersion"]

    # Normalize typical mappings of aid, aip, cid to observables
    aid = commonParsing["aid"]
    cid = commonParsing["cid"]
    aip = commonParsing["aip"]
    
    if aid:
        observables.append(
            {
                "name": "device.agent_list[0].uid",
                "type_id": 10,
                "type": "Resource UID",
                "value": aid
            }
        )
    if cid:
        observables.append(
            {
                "name": "device.uid",
                "type_id": 10,
                "type": "Resource UID",
                "value": cid
            }
        )
    if aip:
        observables.append(
            {
                "name": "device.ip",
                "type_id": 2,
                "type": "IP Address",
                "value": aip
            }
        )

    className = str(baseEventMapping["ClassName"])
    classUid = int(baseEventMapping["ClassUid"])

    ocsf = {
        "activity_name": activityName,
        "activity_id": activityId,
        "category_name": baseEventMapping["CategoryName"],
        "category_uid": baseEventMapping["CategoryId"],
        "class_name": className,
        "class_uid": classUid,
        "severity": baseEventMapping["SeverityName"],
        "severity_id": baseEventMapping["SeverityId"],
        "status": statusName,
        "status_id": statusId,
        "type_name": f"{className}: {activityName}",
        "type_uid": (classUid * 100) + activityId,
        "time": epochToTimestamp(commonParsing["timestamp"]),
        "message": commonParsing["name"],
        "observables": observables,
        "metadata": {
            "uid": commonParsing["id"],
            "log_name": eventName,
            "log_provider": "Falcon Data Replicator",
            "version": "1.2.0",
            "profiles": ["host"],
            "product": {
                "lang": "en",
                "name": "Crowdstrike Falcon",
                "vendor_name": "Crowdstrike",
                "url_string": "https://www.crowdstrike.com/resources/data-sheets/falcon-data-replicator/"
            }
        },
        "device": {
            "ip": aip,
            "uid": cid,
            "os": {
                "type_id": deviceOsTypeUid,
                "type": deviceOsType
            },
            "agent_list": [
                {
                    "uid": aid,
                    "name": "Crowdstrike Falcon Agent",
                    "type_id": 1,
                    "type": "Endpoint Detection and Response",
                    "version": configBuild,
                    "vendor_name": "Crowdstrike"
                }
            ]
        },
        "app": {
            "name": appName,
            "uid": appSource,
            "vendor_name": appVendor,
            "version": appVersion
        },
        "unmapped": unmapped
    }

    return ocsf

def operatingSystemPatchStateeNormalizer(eventName: str, payload: dict) -> dict:
    """Normalizes various FDR events into Operating System Patch State (5004)"""
    baseEventMapping = dict([x for x in QFDR_OCSF_NORMALIZATION if x["EventName"] == eventName][0])

    # Parse common vars in mapped events
    commonParsing = commonFdrParser(payload)
    del payload
    # this is essentially the old payload minus common attributes parsed
    unmapped = dict(commonParsing["unmapped"])
    try:
        configBuild = unmapped["ConfigBuild"]
        del unmapped["ConfigBuild"]
    except KeyError:
        configBuild = None
    try:
        platformType = unmapped["event_platform"]
        del unmapped["event_platform"]
    except KeyError:
        platformType = None

    # Normalize platform type to device.os.type_uid
    if platformType is None:
        deviceOsTypeUid = 0
        deviceOsType = "Unknown"
    elif platformType == "Win":
        deviceOsTypeUid = 100
        deviceOsType = "Windows"
    elif platformType == "Lin":
        deviceOsTypeUid = 200
        deviceOsType = "Linux"
    elif platformType == "Mac":
        deviceOsTypeUid = 300
        deviceOsType = "macOS"
    else:
        deviceOsTypeUid = 99
        deviceOsType = platformType

    # OCSF Arrays, used later...
    observables = []
    kbs = []

    # Parse application_actiivty specific values from various FDR events
    statusFlag = unmapped.get("Status")
    if statusFlag:
        del unmapped["Status"]

        if statusFlag == "0":
            activityId = 1
            activityName = "Install"
            statusId = 1
            statusName = "Success"
        else:
            activityId = 99
            activityName = "Other"
            statusId = 99
            statusName = "Other"
    else:
        activityId = 0
        activityName = "Unknown"
        statusId = 0
        statusName = "Unknown"
    
    installedKbs = unmapped.get("InstalledUpdateIds")
    if installedKbs:
        del unmapped["InstalledUpdateIds"]
        # this can be a multi-value list...
        if ";" in installedKbs:
            for kb in installedKbs.split(";"):
                kbs.append(
                    {
                        "uid": kb
                    }
                )
        else:
            kbs.append(
                {
                    "uid": installedKbs
                }
            )
    else:
        kbs.append(
            {
                "uid": None
            }
        )

    # Normalize typical mappings of aid, aip, cid to observables
    aid = commonParsing["aid"]
    cid = commonParsing["cid"]
    aip = commonParsing["aip"]
    
    if aid:
        observables.append(
            {
                "name": "device.agent_list[0].uid",
                "type_id": 10,
                "type": "Resource UID",
                "value": aid
            }
        )
    if cid:
        observables.append(
            {
                "name": "device.uid",
                "type_id": 10,
                "type": "Resource UID",
                "value": cid
            }
        )
    if aip:
        observables.append(
            {
                "name": "device.ip",
                "type_id": 2,
                "type": "IP Address",
                "value": aip
            }
        )

    className = str(baseEventMapping["ClassName"])
    classUid = int(baseEventMapping["ClassUid"])

    ocsf = {
        "activity_name": activityName,
        "activity_id": activityId,
        "category_name": baseEventMapping["CategoryName"],
        "category_uid": baseEventMapping["CategoryId"],
        "class_name": className,
        "class_uid": classUid,
        "severity": baseEventMapping["SeverityName"],
        "severity_id": baseEventMapping["SeverityId"],
        "status": statusName,
        "status_id": statusId,
        "type_name": f"{className}: {activityName}",
        "type_uid": (classUid * 100) + activityId,
        "time": epochToTimestamp(commonParsing["timestamp"]),
        "message": commonParsing["name"],
        "observables": observables,
        "metadata": {
            "uid": commonParsing["id"],
            "log_name": eventName,
            "log_provider": "Falcon Data Replicator",
            "version": "1.2.0",
            "profiles": [],
            "product": {
                "lang": "en",
                "name": "Crowdstrike Falcon",
                "vendor_name": "Crowdstrike",
                "url_string": "https://www.crowdstrike.com/resources/data-sheets/falcon-data-replicator/"
            }
        },
        "device": {
            "ip": aip,
            "uid": cid,
            "os": {
                "type_id": deviceOsTypeUid,
                "type": deviceOsType
            },
            "agent_list": [
                {
                    "uid": aid,
                    "name": "Crowdstrike Falcon Agent",
                    "type_id": 1,
                    "type": "Endpoint Detection and Response",
                    "version": configBuild,
                    "vendor_name": "Crowdstrike"
                }
            ]
        },
        "kb_article_list": kbs,
        "unmapped": unmapped
    }

    return ocsf

def fileHostingActivityNormalizer(eventName: str, payload: dict) -> dict:
    """Normalizes various FDR events into File Hosting Activity (6006)"""
    baseEventMapping = dict([x for x in QFDR_OCSF_NORMALIZATION if x["EventName"] == eventName][0])

    # Parse common vars in mapped events
    commonParsing = commonFdrParser(payload)
    del payload
    # this is essentially the old payload minus common attributes parsed
    unmapped = dict(commonParsing["unmapped"])
    try:
        configBuild = unmapped["ConfigBuild"]
        del unmapped["ConfigBuild"]
    except KeyError:
        configBuild = None
    try:
        platformType = unmapped["event_platform"]
        del unmapped["event_platform"]
    except KeyError:
        platformType = None

    # OCSF Arrays/Objects, used later...
    observables = []

    # Normalize platform type to device.os.type_uid
    if platformType is None:
        deviceOsTypeUid = 0
        deviceOsType = "Unknown"
    elif platformType == "Win":
        deviceOsTypeUid = 100
        deviceOsType = "Windows"
    elif platformType == "Lin":
        deviceOsTypeUid = 200
        deviceOsType = "Linux"
    elif platformType == "Mac":
        deviceOsTypeUid = 300
        deviceOsType = "macOS"
    else:
        deviceOsTypeUid = 99
        deviceOsType = platformType

    # Parse File Hosting Activity attributes
    fileName = unmapped.get("SourceFileName", None)
    if not fileName:
        fileName = unmapped.get("DownloadPath", None)
    if fileName:
        try:
            del unmapped["SourceFileName"]
        except KeyError:
            del unmapped["DownloadPath"]

        observables.append(
            {
                "name": "file.name",
                "type_id": 7,
                "type": "File Name",
                "value": fileName
            }
        )

    sha256Hash = unmapped.get("SHA256HashData", None)
    if not sha256Hash:
        sha256Hash = unmapped.get("ContentSHA256HashData", None)
    if sha256Hash:
        try:
            del unmapped["SHA256HashData"]
        except KeyError:
            del unmapped["ContentSHA256HashData"]
        observables.append(
            {
                "name": "file.hashes[0].value",
                "type_id": 8,
                "type": "Hash",
                "value": sha256Hash
            }
        )
        hashes = [
            {
                "algorithm_id": 3,
                "algorithm": "SHA-256",
                "value": sha256Hash
            }
        ]
    else:
        hashes = [
            {
                "algorithm_id": None,
                "algorithm": None,
                "value": None
            }
        ]

    downloadServer = unmapped.get("DownloadServer", None)
    if downloadServer:
        del unmapped["DownloadServer"]
        observables.append(
            {
                "name": "dst_endpoint.hostname",
                "type_id": 1,
                "type": "Hostname",
                "value": downloadServer
            }
        )

    downloadPort = unmapped.get("DownloadPort", None)
    if downloadPort:
        downloadPort = int(downloadPort)
        del unmapped["DownloadPort"]
        observables.append(
            {
                "name": "dst_endpoint.port",
                "type_id": 11,
                "type": "Port",
                "value": downloadPort
            }
        )

    # Normalize typical mappings of aid, aip, cid to observables
    aid = commonParsing["aid"]
    cid = commonParsing["cid"]
    aip = commonParsing["aip"]

    if aid:
        observables.append(
            {
                "name": "device.agent_list[0].uid",
                "type_id": 10,
                "type": "Resource UID",
                "value": aid
            }
        )
    if cid:
        observables.append(
            {
                "name": "device.uid",
                "type_id": 10,
                "type": "Resource UID",
                "value": cid
            }
        )
    if aip:
        observables.append(
            {
                "name": "device.ip",
                "type_id": 2,
                "type": "IP Address",
                "value": aip
            }
        )

    className = str(baseEventMapping["ClassName"])
    classUid = int(baseEventMapping["ClassUid"])
    activityId = int(baseEventMapping["ActivityId"])
    activityName = str(baseEventMapping["ActivityName"])

    ocsf = {
        "activity_name": activityName,
        "activity_id": activityId,
        "category_name": baseEventMapping["CategoryName"],
        "category_uid": baseEventMapping["CategoryId"],
        "class_name": className,
        "class_uid": classUid,
        "severity": baseEventMapping["SeverityName"],
        "severity_id": baseEventMapping["SeverityId"],
        "status": baseEventMapping["StatusName"],
        "status_id": baseEventMapping["StatusId"],
        "type_name": f"{className}: {activityName}",
        "type_uid": (classUid * 100) + activityId,
        "time": epochToTimestamp(commonParsing["timestamp"]),
        "message": commonParsing["name"],
        "observables": observables,
        "metadata": {
            "uid": commonParsing["id"],
            "log_name": eventName,
            "log_provider": "Falcon Data Replicator",
            "version": "1.2.0",
            "profiles": [],
            "product": {
                "lang": "en",
                "name": "Crowdstrike Falcon",
                "vendor_name": "Crowdstrike",
                "url_string": "https://www.crowdstrike.com/resources/data-sheets/falcon-data-replicator/"
            }
        },
        "src_endpoint": {
            "ip": aip,
            "uid": cid,
            "os": {
                "type_id": deviceOsTypeUid,
                "type": deviceOsType
            },
            "agent_list": [
                {
                    "uid": aid,
                    "name": "Crowdstrike Falcon Agent",
                    "type_id": 1,
                    "type": "Endpoint Detection and Response",
                    "version": configBuild,
                    "vendor_name": "Crowdstrike"
                }
            ]
        },
        "dst_endpoint": {
            "hostname": downloadServer,
            "port": downloadPort
        },
        "file": {
            "name": fileName,
            "confidentiality_id": 0,
            "confidentiality": "Unknown",
            "hashes": hashes
        },
        "unmapped": unmapped
    }

    return ocsf

def detectionFindingNormalizer(eventName: str, payload: dict) -> dict:
    """Normalizes various FDR events into Detection Finding (2004)"""
    baseEventMapping = dict([x for x in QFDR_OCSF_NORMALIZATION if x["EventName"] == eventName][0])

    # Parse common vars in mapped events
    commonParsing = commonFdrParser(payload)
    del payload
    # this is essentially the old payload minus common attributes parsed
    unmapped = dict(commonParsing["unmapped"])
    try:
        configBuild = unmapped["ConfigBuild"]
        del unmapped["ConfigBuild"]
    except KeyError:
        configBuild = None
    try:
        platformType = unmapped["event_platform"]
        del unmapped["event_platform"]
    except KeyError:
        platformType = None

    # Normalize platform type to device.os.type_uid
    if platformType is None:
        deviceOsTypeUid = 0
        deviceOsType = "Unknown"
    elif platformType == "Win":
        deviceOsTypeUid = 100
        deviceOsType = "Windows"
    elif platformType == "Lin":
        deviceOsTypeUid = 200
        deviceOsType = "Linux"
    elif platformType == "Mac":
        deviceOsTypeUid = 300
        deviceOsType = "macOS"
    else:
        deviceOsTypeUid = 99
        deviceOsType = platformType

    # OCSF Arrays, used later...
    observables = []

    # Parse authentication specific values from various FDR events
    fileName = unmapped.get("ImageFileName", None)
    if fileName:
        del unmapped["ImageFileName"]
        observables.append(
            {
                "name": "evidences[0].process.file.name",
                "type_id": 7,
                "type": "File Name",
                "value": fileName
            }
        )
    
    cmdLine = unmapped.get("CommandLine", None)
    if cmdLine:
        del unmapped["CommandLine"]
        observables.append(
            {
                "name": "evidences[0].process.cmd_line",
                "type_id": 13,
                "type": "Command Line",
                "value": cmdLine
            }
        )

    sha256Hash = unmapped.get("ContentSHA256HashData", None)
    if sha256Hash:
        del unmapped["ContentSHA256HashData"]
        observables.append(
            {
                "name": "evidences[0].process.file.hashes[0].value",
                "type_id": 8,
                "type": "Hash",
                "value": sha256Hash
            }
        )

    contextProcessUid = unmapped.get("ContextProcessId", None)
    if contextProcessUid:
        del unmapped["ContextProcessId"]
    
    parentFileName = unmapped.get("ParentImageFileName", None)
    if parentFileName:
        del unmapped["ParentImageFileName"]
        observables.append(
            {
                "name": "evidences[0].process.parent_process.file.name",
                "type_id": 7,
                "type": "File Name",
                "value": parentFileName
            }
        )
    
    parentCmdLine = unmapped.get("CommandLine", None)
    if parentCmdLine:
        del unmapped["CommandLine"]
        observables.append(
            {
                "name": "evidences[0].process.parent_process.cmd_line",
                "type_id": 13,
                "type": "Command Line",
                "value": parentCmdLine
            }
        )
    
    grandParentFileName = unmapped.get("GrandparentImageFileName", None)
    if grandParentFileName:
        del unmapped["GrandparentImageFileName"]
        observables.append(
            {
                "name": "evidences[0].process.parent_process.parent_process.file.name",
                "type_id": 7,
                "type": "File Name",
                "value": grandParentFileName
            }
        )
    
    grandParentCmdLine = unmapped.get("GrandparentCommandLine", None)
    if grandParentCmdLine:
        del unmapped["GrandparentCommandLine"]
        observables.append(
            {
                "name": "evidences[0].process.parent_process.parent_process.cmd_line",
                "type_id": 13,
                "type": "Command Line",
                "value": grandParentCmdLine
            }
        )
    # Normalize typical mappings of aid, aip, cid to observables
    aid = commonParsing["aid"]
    cid = commonParsing["cid"]
    aip = commonParsing["aip"]
    
    if aid:
        observables.append(
            {
                "name": "device.agent_list[0].uid",
                "type_id": 10,
                "type": "Resource UID",
                "value": aid
            }
        )
    if cid:
        observables.append(
            {
                "name": "device.uid",
                "type_id": 10,
                "type": "Resource UID",
                "value": cid
            }
        )
    if aip:
        observables.append(
            {
                "name": "device.ip",
                "type_id": 2,
                "type": "IP Address",
                "value": aip
            }
        )

    className = str(baseEventMapping["ClassName"])
    classUid = int(baseEventMapping["ClassUid"])
    activityId = int(baseEventMapping["ActivityId"])
    activityName = str(baseEventMapping["ActivityName"])

    ocsf = {
        "activity_name": activityName,
        "activity_id": activityId,
        "category_name": baseEventMapping["CategoryName"],
        "category_uid": baseEventMapping["CategoryId"],
        "class_name": className,
        "class_uid": classUid,
        "severity": baseEventMapping["SeverityName"],
        "severity_id": baseEventMapping["SeverityId"],
        "status": baseEventMapping["StatusName"],
        "status_id": baseEventMapping["StatusId"],
        "type_name": f"{className}: {activityName}",
        "type_uid": (classUid * 100) + activityId,
        "time": epochToTimestamp(commonParsing["timestamp"]),
        "message": commonParsing["name"],
        "observables": observables,
        "metadata": {
            "uid": commonParsing["id"],
            "log_name": eventName,
            "log_provider": "Falcon Data Replicator",
            "version": "1.2.0",
            "profiles": ["host"],
            "product": {
                "lang": "en",
                "name": "Crowdstrike Falcon",
                "vendor_name": "Crowdstrike",
                "url_string": "https://www.crowdstrike.com/resources/data-sheets/falcon-data-replicator/"
            }
        },
        "device": {
            "ip": aip,
            "uid": cid,
            "os": {
                "type_id": deviceOsTypeUid,
                "type": deviceOsType
            },
            "agent_list": [
                {
                    "uid": aid,
                    "name": "Crowdstrike Falcon Agent",
                    "type_id": 1,
                    "type": "Endpoint Detection and Response",
                    "version": configBuild,
                    "vendor_name": "Crowdstrike"
                }
            ]
        },
        "evidences": [
            {
                "process": {
                    "cmd_line": cmdLine,
                    "uid": contextProcessUid,
                    "file": {
                        "name": fileName,
                        "hashes": [
                            {
                                "algorithm": "SHA-256",
                                "algorithm_id": 3,
                                "value": sha256Hash
                            }
                        ]
                    },
                    "parent_process": {
                        "cmd_line": parentCmdLine,
                        "file": {
                            "name": parentFileName
                        },
                        "parent_process": {
                            "cmd_line": grandParentCmdLine,
                            "file": {
                                "name": grandParentFileName
                            }
                        }
                    }
                }
            }
        ],
        "unmapped": unmapped
    }

    return ocsf

###