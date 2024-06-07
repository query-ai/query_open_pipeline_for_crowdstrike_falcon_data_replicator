import logging

logger = logging.getLogger()
logging.basicConfig(level=logging.INFO)

import argparse
import json
import boto3
import boto3.session
from botocore.exceptions import ClientError
from sys import exit as sysexit

parser = argparse.ArgumentParser(description="Input AWS values")

parser.add_argument(
    "--firehose_metadata_file_name",
    help="Name of the JSON metadata file that contains naming conventions for Firehose, Glue transformation tables, Custom Sources, and more.",
    default="qopcfdr_firehose_metadata_template.json",
    type=str
)
parser.add_argument(
    "--firehose_role_arn",
    help="ARN for the AWS IAM Role for all Firehose Data Streams deployed by CloudFormation.",
    type=str
)
parser.add_argument(
    "--log_group_name",
    help="Name to give a Log Group that all Firehoses will share.",
    default="qopcfdr-firehose-logs",
    type=str
)
parser.add_argument(
    "--deployment_mode",
    choices=["create", "delete"],
    default="create",
    type=str
)

try:
    args=parser.parse_args()
    firehoseMetadataFileName = args.firehose_metadata_file_name
    firehoseRoleArn = args.firehose_role_arn
    logGroupName = args.log_group_name
    mode = args.deployment_mode
except TypeError:
    logger.error("One or all of the provided arguments were blank. Please provide values for all args and try again.")
    sysexit(2)

# necessary Boto3 clients
sts = boto3.client("sts")
cwl = boto3.client("logs")
firehose = boto3.client("firehose")
session = boto3.session.Session()
awsRegion = session.region_name
customSourceAcctId = sts.get_caller_identity()["Account"]

with open(firehoseMetadataFileName) as classmapper:
    qopcfdrClassEventMapping = list(json.load(classmapper))

def partitionMapper(region: str):
    """
    Returns the AWS Partition based on the current Region of a Session
    """
    # GovCloud partition override
    if region in ["us-gov-east-1", "us-gov-west-1"] or "us-gov-" in region:
        partition = "aws-us-gov"
    # China partition override
    elif region in ["cn-north-1", "cn-northwest-1"] or "cn-" in region:
        partition = "aws-cn"
    # AWS Secret Region override
    elif region in ["us-isob-east-1", "us-isob-west-1"] or "isob-" in region:
        partition = "aws-isob"
    # AWS UKSOF / British MOD Region override
    elif "iso-e" in region or "isoe" in region:
        partition = "aws-isoe"
    # AWS Intel Community us-isof-south-1 Region override
    elif region in ["us-isof-south-1"] or "iso-f" in region or "isof" in region:
        partition = "aws-isof"
    # AWS Top Secret Region override
    elif region in ["us-iso-east-1", "us-iso-west-1"] or "iso-" in region:
        partition = "aws-iso"
    # TODO: Add European Sovreign Cloud Partition
    else:
        partition = "aws"

    return partition

partition = partitionMapper(region=awsRegion)

def createLogGroup():
    """Creates a single Log Group"""
    try:
        cwl.create_log_group(logGroupName=logGroupName)
        logger.info("Log Group created!")
    except ClientError as err:
        if "ResourceAlreadyExistsException" in str(err):
            logger.info("Log Group with name %s already exists, continuing...")
        else:
            logger.error("Could not create Log Group because: %s", err)
            sysexit(2)

def parseEventNames():
    """Loops through mapped FDR Event to OCSF Class mappings and formats them for naming and event class args"""
    for event in qopcfdrClassEventMapping:
        className = event["ClassName"]
        firehoseName = event["FirehoseName"]
        glueTransformationTableName = event["GlueTransformationTableName"]
        customSourceName = event["CustomSourceName"]
        customSourceLocation = event["CustomSourceS3Location"]
    
        createCustomSourceFirehoseStream(
            className,
            firehoseName,
            glueTransformationTableName,
            customSourceName,
            customSourceLocation
        )

def createCustomSourceFirehoseStream(className: str, firehoseName: str, glueTransformationTableName: str, customSourceName: str, customSourceLocation: str):
    """Creates a Firehose delivery stream that uses Glue schema tables and S3 locations from Sec Lake custom sources"""

    locationPrefix = customSourceLocation.split("/ext")[1]
    sourceBucket = customSourceLocation.split("s3://")[1].split("/ext")[0]
    sourceBucketArn = f"arn:{partition}:s3:::{sourceBucket}"

    try:
        firehose.create_delivery_stream(
            DeliveryStreamName=firehoseName,
            DeliveryStreamType="DirectPut",
            DeliveryStreamEncryptionConfigurationInput={
                "KeyType": "AWS_OWNED_CMK"
            },
            ExtendedS3DestinationConfiguration={
                "RoleARN": firehoseRoleArn,
                "BucketARN": sourceBucketArn,
                "Prefix": f"ext{locationPrefix}region={awsRegion}/accountId={customSourceAcctId}" + "/eventDay=!{partitionKeyFromQuery:year}!{partitionKeyFromQuery:month}!{partitionKeyFromQuery:day}/",
                "ErrorOutputPrefix": "failures/" + customSourceName + "/!{firehose:error-output-type}/",
                "BufferingHints": {
                    "SizeInMBs": 128,
                    "IntervalInSeconds": 180
                },
                "CloudWatchLoggingOptions": {
                    "Enabled": True,
                    "LogGroupName": logGroupName,
                    "LogStreamName": firehoseName
                },
                "ProcessingConfiguration": {
                    "Enabled": True,
                    "Processors": [
                        {
                            "Type": "MetadataExtraction",
                            "Parameters": [
                                {
                                    "ParameterName": "JsonParsingEngine",
                                    "ParameterValue": "JQ-1.6"
                                },
                                {
                                    "ParameterName": "MetadataExtractionQuery",
                                    "ParameterValue": '{year:.time| strptime("%Y-%m-%d %H:%M:%S.%Z")| strftime("%Y"),month:.time| strptime("%Y-%m-%d %H:%M:%S.%Z")| strftime("%m"),day:.time| strptime("%Y-%m-%d %H:%M:%S.%Z")| strftime("%d")}'
                                }
                            ]
                        }
                    ]
                },
                "DataFormatConversionConfiguration": {
                    "Enabled": True,
                    "SchemaConfiguration": {
                        "RoleARN": firehoseRoleArn,
                        "CatalogId": customSourceAcctId,
                        "DatabaseName": "query_open_pipeline_for_fdr_firehose_etl_schemas",
                        "TableName": glueTransformationTableName,
                        "Region": awsRegion,
                        "VersionId": "LATEST"
                    },
                    "InputFormatConfiguration": {
                        "Deserializer": {
                            "OpenXJsonSerDe": {}
                        }
                    },
                    "OutputFormatConfiguration": {
                        "Serializer": {
                            "ParquetSerDe": {
                                "Compression": "GZIP"
                            }
                        }
                    }
                },
                "DynamicPartitioningConfiguration": {
                    "Enabled": True
                }
            },
            Tags=[
                {
                    "Key": "Name",
                    "Value": firehoseName
                },
                {
                    "Key": "Description",
                    "Value": f"Write Crowdstrike FDR data events that match OCSF class {className} to Security Lake"
                },
                {
                    "Key": "OCSFClassName",
                    "Value": className
                },
                {
                    "Key": "SecurityLakeCustomSourceName",
                    "Value": customSourceName
                }
            ]
        )
        logger.info("Created Firehose Delivery Stream %s", firehoseName)
    except ClientError as err:
        if "ResourceInUseException" in err:
            logger.info("Firehose Delivery Stream %s already exists, continuing...", firehoseName)
        else:
            logger.error(
                "Could not create Firehose Delivery Stream %s for class name %s with transformation table %s because: %s",
                firehoseName,className,glueTransformationTableName,err
            )
            sysexit(2)

def removeFirehose():
    """Deletes all Firehoses"""
    try:
        for stream in firehose.list_delivery_streams(Limit=1000,DeliveryStreamType="DirectPut")["DeliveryStreamNames"]:
            print(stream)
            if "qopcfdr_" in stream:
                firehose.delete_delivery_stream(
                    DeliveryStreamName=stream,
                    AllowForceDelete=True
                )
                
                logger.info("Removed stream %s", stream)
    except ClientError as err:
        logger.error("Could not list or delete Firehose streams because: %s")
        sysexit(2)

if mode == "create":
    createLogGroup()
    parseEventNames()
else:
    removeFirehose()

#