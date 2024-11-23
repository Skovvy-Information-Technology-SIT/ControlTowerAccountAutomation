# Automated Security Services and VPC Flow Logs using AWS Control Tower lifecycle event

This solution automates the deployment of security services and the creation of **VPC Flow Logs** in newly created AWS accounts managed by **AWS Control Tower**. The solution uses **AWS CloudFormation**, **Lambda**, and **Amazon EventBridge** to automatically provision security services such as **Security Hub**, **GuardDuty**, **AWS Config**, **Inspector**, **CloudWatch Alarms**, and **VPC Flow Logs** when a new account is created in Control Tower.

The core infrastructure for automating this solution is built using **AWS CloudFormation CloudFormation Templates (CfCT)**, providing a scalable and repeatable way to deploy these resources.


![image](https://github.com/user-attachments/assets/9ee08140-173b-479f-8c70-457c4ee87f62)


## Overview

1. **CloudFormation Stack**: The CloudFormation template deploys critical security services and enables **VPC Flow Logs** for monitoring VPC traffic.
2. **Lambda Function**: The Lambda function is triggered by **AWS Control Tower lifecycle events** (e.g., when a new account is created), which deploys the CloudFormation stack.
3. **EventBridge Rule**: Captures `AWSControlTowerAccountCreated` lifecycle events and invokes the Lambda function to deploy the CloudFormation stack.
4. **IAM Role**: Lambda execution role has necessary permissions to create resources such as CloudFormation stacks, GuardDuty detectors, Security Hub, VPC Flow Logs, etc.

## Solution Components

1. **CloudFormation Template**: Defines security services like **Security Hub**, **GuardDuty**, **AWS Config**, **Inspector**, **CloudWatch Alarms**, and **VPC Flow Logs**.
2. **Lambda Function**: This function is triggered by EventBridge rules to deploy the CloudFormation stack for newly created accounts.
3. **IAM Permissions**: The Lambda function needs specific permissions to interact with AWS services such as CloudFormation, EC2 (for flow logs), and CloudWatch Logs.

---

## 2. Lambda Function to Deploy CloudFormation Stack

This Lambda function triggers when an **AWS Control Tower lifecycle event** (specifically `AWSControlTowerAccountCreated`) occurs. The function will deploy the CloudFormation stack to create security services and enable **VPC Flow Logs**.

```python
import json
import boto3
import logging
import os

# Initialize CloudFormation client
cf_client = boto3.client('cloudformation')
logs_client = boto3.client('logs')
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    try:
        # Log the event details for troubleshooting
        logger.info("Received event: %s", json.dumps(event))

        # Check if this is the account creation event from Control Tower
        if event['detail-type'] == 'AWS Control Tower Account Created':
            account_id = event['detail']['accountId']
            logger.info(f"New account created: {account_id}")

            # Define CloudFormation stack parameters
            stack_name = f"SecurityServicesStack-{account_id}"
            template_file_path = '/path/to/your/cloudformation_template.yaml'  # Adjust path to your CloudFormation template

            # Read the CloudFormation template
            with open(template_file_path, 'r') as template_file:
                template_body = template_file.read()

            # Create the CloudFormation stack to deploy security services and VPC Flow Logs
            response = cf_client.create_stack(
                StackName=stack_name,
                TemplateBody=template_body,
                Parameters=[
                    {
                        'ParameterKey': 'AccountId',
                        'ParameterValue': account_id
                    }
                ],
                Capabilities=['CAPABILITY_NAMED_IAM']  # Allow named IAM roles
            )

            # Log the response for debugging
            logger.info(f"CloudFormation stack creation initiated: {response}")

        else:
            logger.info("Event is not related to account creation, skipping.")

    except Exception as e:
        logger.error(f"Error processing event: {str(e)}")
        raise e
```
## 3. EventBridge Rule Configuration

Create an Amazon EventBridge Rule to capture Control Tower lifecycle events (e.g., AWSControlTowerAccountCreated) and invoke the Lambda function.

EventBridge Rule

```
{
  "Source": [
    "aws.controltower"
  ],
  "DetailType": [
    "AWS Control Tower Account Created"
  ],
  "Detail": {}
}
```
## 4. Lambda Execution Role
Ensure that the Lambda function has the necessary permissions to interact with AWS services such as CloudFormation, EC2 (for flow logs), CloudWatch Logs, and IAM roles.

Here is an example IAM policy that should be attached to your Lambda function’s execution role:

```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "cloudformation:CreateStack",
        "cloudformation:DescribeStacks",
        "cloudformation:UpdateStack",
        "iam:PassRole",
        "ec2:CreateFlowLogs",
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "config:PutConfigurationRecorder",
        "securityhub:EnableSecurityHub",
        "guardduty:CreateDetector"
      ],
      "Resource": "*"
    }
  ]
}
````
## 5. Testing and Monitoring

### Test the Setup:
Provision a New Account: Create a new account in AWS Control Tower.
EventBridge captures the AWSControlTowerAccountCreated event and triggers the Lambda function.
The Lambda function deploys the CloudFormation stack, which includes the VPC Flow Logs and other security resources.

### Monitoring:
Lambda Logs: Monitor logs in CloudWatch for Lambda execution details.
CloudFormation Logs: Check the CloudFormation stack events in the AWS Console to ensure that the resources were successfully created.
VPC Flow Logs: Logs will be available in the CloudWatch log group (/aws/vpc/flowlogs/{account_id}).

## Summary
This solution provides automated security configuration for new AWS Control Tower accounts. Upon creation of an account, the solution deploys security services (Security Hub, GuardDuty, etc.) and enables VPC Flow Logs for network monitoring. The solution is built using AWS CloudFormation (CfCT), Lambda, and EventBridge for seamless automation.
