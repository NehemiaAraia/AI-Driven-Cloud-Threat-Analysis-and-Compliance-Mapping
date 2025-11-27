<p align="center">
  <h1 align="center">AI Driven Cloud Threat Analysis and Compliance Mapping</h1>
  <p align="center">
    For this project, I created a fully automated AI-powered cloud incident processing system deployed through AWS CloudFormation. It uses Amazon Bedrock to generate summaries of GuardDuty findings, correlates the alerts with CloudTrail logs, maps each threat to NIST and CIS requirements, and stores structured incident data in DynamoDB for long-term tracking. The pipeline automatically generates clean HTML and JSON incident reports and sends an email alert with an AI summary so teams can quickly understand and respond to potential threats.<br />
  </p>
</p>

## Features


- **AWS CloudFormation**
- **Amazon Bedrock**
- **Amazon Guardduty**
- **Amazon DynamoDB**
- **Amazon SNS**
- **AWS IAM**
- **AWS CloudTrail**
- **AWS Lambda**
- **Amazon S3**
- **NIST 800-53**
- **CIS Controls**
- **MITRE ATT&CK**


## Step 1.
To start this project, I set up a clean folder structure for the CloudFormation template and Lambda code, then configured the full infrastructure definition that creates the Lambda function, EventBridge rule, IAM roles, DynamoDB table, S3 bucket, and SNS topic. After reviewing the architecture in Infrastructure Composer to confirm the relationships between services, I deployed the template in CloudFormation, which automatically provisioned the entire pipeline in my AWS account.

<img width="1470" height="805" alt="Infrastructure Diagram" src="https://github.com/user-attachments/assets/efa5ccd6-1181-452b-91c7-00711f348bd4" />

## Step 2.
Once the CloudFormation stack was launched, I waited a few minutes for all resources to finish deploying. After everything was shown to be complete, I verified that each service was configured correctly. This included checking that the S3 bucket, DynamoDB table, SNS topic, EventBridge rule, and Lambda function were all active and connected as expected, ensuring the incident pipeline was ready to process incoming findings.

<img width="1470" height="832" alt="Template Complete" src="https://github.com/user-attachments/assets/16942100-bada-4e6f-957c-59a944c61ca4" />

## Step 3.
Once everything finished creating, I moved into testing and validating the Lambda function. I checked the environment variables, confirmed the IAM permissions for DynamoDB, S3, SNS, CloudTrail, and Bedrock. During this stage, I ran into a few issues and spent time troubleshooting by investigating the logs in CloudWatch, updating the code, and fixing formatting problems until the function executed cleanly and was able to process findings.

<img width="1470" height="832" alt="Lambda Function" src="https://github.com/user-attachments/assets/c4bf34bf-637c-470d-8efa-7e25268bffc1" />

## Step 4.
After everything finished deploying, I generated new sample findings in GuardDuty and went to the Summary page to make sure they appeared correctly. From this screen, I could see the total number of findings, the severity distribution, and how many resources were affected. This confirmed that GuardDuty was active and producing the data needed for my incident pipeline.

<img width="1470" height="832" alt="Guardduty" src="https://github.com/user-attachments/assets/ebe823ce-42d8-490a-bdba-f8c87686185f" />

## Step 5.
After reviewing the summary, I went into the Findings page where GuardDuty listed every individual alert. I could see a wide range of high-severity sample findings across different threat types, each showing the affected resource, the finding category, and the severity badge. This confirmed that GuardDuty was actively generating realistic security events for my pipeline to process.

<img width="1470" height="832" alt="Guardduty finding" src="https://github.com/user-attachments/assets/7a115a4c-6141-4178-9006-e6e24e751e7e" />

## Step 6.
Once the system was fully deployed and connected to GuardDuty, I started receiving a continuous stream of incident notifications in my email. Every time GuardDuty generated a new finding, the pipeline automatically processed it, generated a report, and sent an alert through Amazon SNS. I could see dozens of alerts coming in one after another, which confirmed that the Lambda function, CloudTrail correlation, and AI summarization workflow were all firing correctly.

<img width="1470" height="832" alt="Email Notifcations" src="https://github.com/user-attachments/assets/a08de3e9-2f60-4d63-b6f7-bed6adeb4a35" />

## Step 7.
When I opened any of the individual notifications, I could see a detailed summary of the incident, including the mapped NIST and CIS controls, assigned MITRE ATT&CK tags, and a short AI generated explanation of what happened. Each email also included links to both the JSON and HTML reports stored in S3, making it easy to review the full incident history and context directly from the alert.

<img width="1470" height="832" alt="Final Email" src="https://github.com/user-attachments/assets/b7f6bc11-75ef-41d8-8f67-52cae6af1dbb" />







