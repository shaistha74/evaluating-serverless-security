import json
import boto3
import os
from datetime import datetime

ec2_client = boto3.client('ec2')
s3_client = boto3.client('s3')
sns_client = boto3.client('sns')

def lambda_handler(event, context):
    print("Incoming event payload:")
    print(json.dumps(event, indent=2))

    # Archiving logs to S3 bucket
    try:
        log_event_to_s3(event, context)
    except Exception as log_error:
        print(f"S3 log archival failed: {log_error}")

    # Performing remediation
    detail = event.get("detail", {})
    title = detail.get("title", "Unnamed Alert")
    resource_data = detail.get("resource", {})
    resource_type = resource_data.get("resourceType", "")

    actions_taken = []
    instance_id = resource_data.get("instanceDetails", {}).get("instanceId", "")

    if resource_type == "Instance" and instance_id:
        detach_network_interface(instance_id)
        actions_taken.append(f"Detached ENI from EC2 instance: {instance_id}")

    elif resource_type == "AccessKey" or "S3Bucket" in json.dumps(resource_data):
        s3_bucket = parse_s3_bucket_name(title)
        if s3_bucket:
            apply_s3_security_policy(s3_bucket)
            actions_taken.append(f"Applied S3 bucket policies to: {s3_bucket}")

    if not actions_taken:
        actions_taken.append("No specific remediation carried out. Manual review advised.")

    notify_remediation_result(title, actions_taken)

    return {
        "statusCode": 200,
        "body": json.dumps({"message": "Lambda completed.", "actions": actions_taken})
    }

def log_event_to_s3(event, context):
    service = event.get("source", "unknown").split('.')[-1]
    timestamp = datetime.utcnow().strftime('%Y/%m/%d')
    s3_key_path = f"{service}/{timestamp}/{context.aws_request_id}.json"

    s3_client.put_object(
        Bucket=os.environ["LOG_BUCKET"],
        Key=s3_key_path,
        Body=json.dumps(event, separators=(',', ':')),
        ContentType="application/json"
    )
    print(f"Event archived to s3://{os.environ['LOG_BUCKET']}/{s3_key_path}")

def detach_network_interface(instance_id): # if threat is detected and affected resource is ec2 then gets dettached from the network
    try:
        response = ec2_client.describe_instances(InstanceIds=[instance_id])
        interface = response["Reservations"][0]["Instances"][0]["NetworkInterfaces"][0]
        eni_id = interface["NetworkInterfaceId"]
        attachment_id = interface["Attachment"]["AttachmentId"]

        ec2_client.modify_network_interface_attribute(
            NetworkInterfaceId=eni_id,
            Attachment={"AttachmentId": attachment_id, "DeleteOnTermination": True}
        )
        ec2_client.detach_network_interface(AttachmentId=attachment_id, Force=True)

        print(f"Detached ENI {eni_id} from instance {instance_id}")
    except Exception as e:
        print(f"Error during EC2 isolation: {e}")

def apply_s3_security_policy(bucket): # If the affected resource is S3 bucket or access key, then bucket is secured using the Public Access Block and ACL settings.
    try:
        s3_client.put_public_access_block(
            Bucket=bucket,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True
            }
        )
        s3_client.put_bucket_acl(Bucket=bucket, ACL="private")
        print(f"S3 bucket {bucket} has been secured.")
    except Exception as e:
        print(f"Error applying S3 security policy: {e}")

def parse_s3_bucket_name(text):
    for word in text.split():
        if word.startswith("s3://"):
            return word.replace("s3://", "")
        elif ".s3.amazonaws.com" in word:
            return word.split(".s3")[0]
    return None

def notify_remediation_result(title, actions):
    try:
        sns_client.publish(
            TopicArn=os.environ["SNS_TOPIC"],
            Subject=f"Remediation Triggered: {title}",
            Message="\n".join(actions)
        )
        print("Notification sent via SNS.")
    except Exception as e:
        print(f"Notification failed: {e}")
