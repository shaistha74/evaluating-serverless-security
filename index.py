import json
import boto3
import os

ec2 = boto3.client('ec2')
s3 = boto3.client('s3')
sns = boto3.client('sns')

def handler(event, context):
    print("Received event:", json.dumps(event, indent=2))

    detail = event.get("detail", {})
    title = detail.get("title", "No title")
    resource = detail.get("resource", {})
    resource_type = resource.get("resourceType", "")

    remediation_actions = []
    instance_id = resource.get("instanceDetails", {}).get("instanceId", "")

    # EC2 Instance Isolation
    if resource_type == "Instance" and instance_id:
        isolate_ec2_instance(instance_id)
        remediation_actions.append(f"Isolated EC2 instance: {instance_id}")

    # S3 Bucket Remediation
    elif resource_type == "AccessKey" or "S3Bucket" in json.dumps(resource):
        bucket_name = extract_bucket_name(title)
        if bucket_name:
            remediate_s3_bucket(bucket_name)
            remediation_actions.append(f"Secured S3 bucket: {bucket_name}")

    # Fallback if nothing was done
    if not remediation_actions:
        remediation_actions.append("No remediation actions performed. Review event manually.")

    # Send SNS Alert 
    send_sns_notification(title, remediation_actions)

    return {
        'statusCode': 200,
        'body': json.dumps('Remediation executed')
    }
# EC2 Isolation Function
def isolate_ec2_instance(instance_id):
    try:
        response = ec2.describe_instances(InstanceIds=[instance_id])
        eni = response['Reservations'][0]['Instances'][0]['NetworkInterfaces'][0]
        eni_id = eni['NetworkInterfaceId']
        attachment_id = eni['Attachment']['AttachmentId']

        ec2.modify_network_interface_attribute(
            NetworkInterfaceId=eni_id,
            Attachment={
                'AttachmentId': attachment_id,
                'DeleteOnTermination': True
            }
        )

        ec2.detach_network_interface(
            AttachmentId=attachment_id,
            Force=True
        )

        print(f"Isolated EC2 instance {instance_id} by detaching ENI {eni_id}")
    except Exception as e:
        print(f"Error isolating EC2 instance {instance_id}: {e}")

# S3 Bucket Remediation
def remediate_s3_bucket(bucket_name):
    try:
        s3.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        )
        s3.put_bucket_acl(Bucket=bucket_name, ACL='private')
        print(f"S3 bucket {bucket_name} has been secured.")
    except Exception as e:
        print(f"Error securing S3 bucket {bucket_name}: {e}")

# Extract S3 Bucket Name
def extract_bucket_name(text):
    words = text.split()
    for word in words:
        if word.startswith("s3://"):
            return word.replace("s3://", "")
        elif ".s3.amazonaws.com" in word:
            return word.split(".s3")[0]
    return None

# SNS Notification
def send_sns_notification(title, actions):
    try:
        sns.publish(
            TopicArn=os.environ['SNS_TOPIC'],
            Subject=f"AWS Auto-Remediation: {title}",
            Message="\n".join(actions)
        )
        print("SNS notification sent.")
    except Exception as e:
        print(f"Error sending SNS notification: {e}")
