# Query Open Pipeline for Crowdstrike Falcon Data Replicator

Query Open Pipeline for Crowdstrike Falcon Data Replicator (QOPCFDR) is an AWS native data mobility solution for Crowdstrike Falcon Data Replicator ETL into the Amazon Security Lake in OCSF v1.2.0 format.

QOPCFDR facilitates the mobility of streaming (and historical archives) of [Crowdstrike Falcon Data Replicator](https://www.crowdstrike.com/resources/data-sheets/falcon-data-replicator/) (FDR) data. FDR is a mechanism provided by Crowdstrike to: "Collect events in near real time from your Falcon endpoints and cloud workloads, identities and data, enriched by the AI-powered Crowdstrike Security Cloud."

FDR data provides incredibly rich and near real-time sensor-level data as well as other events such as interactions with the Crowdstrike API, identities, and other data points for use by incident response, threat hunting, and detection engineering teams. Crowdstrike provides [a Python script](https://github.com/CrowdStrike/FDR) that will poll your FDR-dedicated [Amazon Simple Queue Service (SQS)](https://aws.amazon.com/sqs/?nc2=h_ql_prod_ap_sqs) queue, download and parse objects containing FDR data from an Amazon S3 bucket, and write it to your own Amazon S3 bucket or local filesystem.

From that point forward is where QOPCFDR serves as an asset. Using Amazon Web Services (AWS) Cloud native services from analytics, application integration, serverless compute, and storage QOPCFDR handles batching, Extraction, Transformation, and Loading (ETL) of raw Crowdstrike FDR data into normalized and standardized [Open Cyber Security Format (OCSF)](https://github.com/ocsf/ocsf-docs/blob/main/Understanding%20OCSF.pdf?extensions=) [version 1.2.0](https://schema.ocsf.io/1.2.0/) and makes it available to the [Amazon Security Lake](https://aws.amazon.com/security-lake/).

As a community project we hope that current consumers of Crowdstrike FDR and/or the Amazon Security Lake find this solution beneficial. Additionally, given the wide breadth of FDR data that come from different operating systems, Crowdstrike licensing tiers, and capture operations - we only have a small snapshot (~120 events) of the nearly 1000 FDR events. We will accept pull requests to improve normalization, to expand mapped events, and share mappings.

## Solution Architecture

![QOPCFDR Solution Architecture](./media/QOPCFDR_Architecture.jpg)

From the bottom-left quadrant, the workflow is as follows:

1. Using the FDR Python script, FDR raw data is written into an Amazon S3 bucket.

2. An [Amazon EventBridge](https://aws.amazon.com/eventbridge/) Rule [monitors the S3 bucket](https://repost.aws/knowledge-center/eventbridge-rule-monitors-s3) for `ObjectCreation` events (Put, Copy, MultiPartUploadComplete) for FDR data being written (only `.gz` files).

3. EventBridge sends the objects to an SQS queue which batches the objects to an [AWS Lambda](https://aws.amazon.com/lambda/?nc2=h_ql_prod_fs_lbd) function.

4. The first Lambda function will parse and normalize the raw FDR data into JSON format, and send specific events to the appropriate upstream SQS queues based on the mapping of an FDR event to an [OCSF Class](https://schema.ocsf.io/1.2.0/classes?extensions=).

5. These subsequent SQS Queues batch up transformed data to Lambda functions which write into batches to dedicated [Amazon Data Firehose](https://aws.amazon.com/firehose/) Delivery Streams.

6. Data Firehose transforms the JSON data into [Parquet](https://parquet.apache.org/) format using schemas stored in [AWS Glue](https://aws.amazon.com/glue/) tables, and dynamically partitions the data in an appropriate format for Security Lake.

7. Each Firehose writes the GZIP-compressed Parquet data into [partitions](https://aws.amazon.com/blogs/big-data/get-started-managing-partitions-for-amazon-s3-tables-backed-by-the-aws-glue-data-catalog/) within a specific S3 location that matches an Amazon Security Lake Custom Source.

8. End-users can query the FDR Security Lake tables using [Amazon Athena](https://aws.amazon.com/athena/) - a [Trino](https://trino.io/)-based serverless analytics engine - or by using [Query.ai's Federated Search](https://www.query.ai/) platform.

9. Your analysts are very happy to use FDR data!

All services except for the Amazon Security Lake Custom Sources (and supporting ancillary services which are auto-created/auto-invoked) are deployed using AWS CloudFormation stacks. Refer to the [Prequisites & Assumptions](#prequisites--assumptions) and [Known limitations](#known-limitations) sections for information about what you need to do, and limitations around QOPCFDR, respectively.

## Prequisites & Assumptions

- DO NOT CHANGE ANY HARD CODED NAMES! To streamline deployment, a lot of names are hardcoded to avoid complex interpolation logic or repeated manual data entry (such as giving the wrong Firehose or SQS Queue name to the wrong Lambda function).
- Crowdstrike Falcon Data Replicator is enabled in your tenant
- You use Crowdstrike's Python script for writing FDR data to Amazon S3
- You have Security Lake enabled in at least one Account and Region
- You have a separate security data collection account from your Security Lake Delegated Administrator, while this solution *can* work, additional Lake Formation permissions issues may arise that have not been tested.
- You have Admin access to your data collection and Security Lake account and can interact with various APIs from Lake Formation, Glue, S3, IAM, Firehose, SQS, and more.

## Known Limitations

- This is a Security Lake-only integration, in the future we may expand to other Lakehouses using open source data orchestration projects.
- There is no utility to bulk-move previously saved FDR data. The best mechanism is to copy existing and future FDR dumps into a new bucket and key the automation off of it. In the future we are considering developing an EMR Notebook to utilize PySpark for petabyte scale mobility into the Security Lake.
- Only 122 out of 950+ Falcon Data Replicator event types are supported due to the size and scope of our environment. Nearly every Windows events and mobile events are missing. Advanced licensing data is missing from FDR as well. Please see the **Expanding Coverage** section for more information on contributing mappings or providing us data.
- Only the raw FDR events are normalized, other structured data from `aidmaster` and `manageddevice` is **NOT NORMALIZED NOR USED**.
- Not every potential normalization is known, and the normalization is written against OCSF v1.2.0.
- Simplistic exponential backoff built into Boto3 and Python is used for moving data between services - there can be times (depending on volume) where Firehose is throttled - Dead Letter Queues (DLQ) and more resilient retry logic will be developed at a later date.

## Deployment Steps

### Prepare the Security Lake Admin Account

The following steps must take place in the AWS Account where Amazon Security Lake is deployed. For the best configuration, deploy this into the (Delgated) Administrator account in your primary or "home" Roll-Up Region where all other Security Lake data flows.

1. Deploy the [`QOPCFDR_SchemaTransformation_CFN.yaml`](./src/cfn_yaml/QOPCFDR_SchemaTransformation_CFN.yaml) CloudFormation stack. This Stack deploys Glue Tables used by Firehose to translate JSON OCSF to Parquet, deploys necessary IAM Roles, and applies LakeFormation permissions to the Roles.

2. In the output of the Stack, copy all three of the ARNs for the Roles, as they will be needed in future steps as shown below. The immediate one that is needed is the Glue Crawler ARN. This has Lake Formation permissions and IAM permissions to crawl the FDR data written to the Security Lake S3 Bucket.

![Step 2](./media/step2.png)

3. Manually create Custom Sources using the Custom Source Name and Class Name detailed in [`qopcfdr_firehose_metadata_template.json`](./src/json/qopcfdr_firehose_metadata_template.json). As of 7 JUNE 2024 you will need to manually create 13

Ensure you add the full S3 URI (including `s3://` and the trailing `/`) into the JSON file. Use the ARN of the Crawler Role deployed by the CFN.

- Execute the `create_qopcfdr_firehoses.py` script, providing an argument of the Firehose Role name and optionally the location of the metadata JSON if it is not in your current working directory. This will create Firehose Delivery Streams that use the deployed Glue tables and the IAM Role.

### In the FDR Source Account
(or Sec Lake Admin account if FDR raw data is stored there)

- Identify the bucket where you will copy/write FDR day into. Ensure the setting `Send notifications to Amazon EventBridge for all events in this bucket` is enabled.

- Upload `QFDR_OCSF_Mapping.json`, `mapped_qfdr_events_to_class.json`, and `qopcfdr_stream_loader.py` into a (separate) S3 bucket.

- Deploy the `QOPCFDR_RealTimeCollection_CFN.yaml` Stack. This stack creates an EventBridge Rule, SQS Queues, Lambda functions, and IAM roles that facilitate the batching and queueing of FDR data from its raw form into the Security Lake.