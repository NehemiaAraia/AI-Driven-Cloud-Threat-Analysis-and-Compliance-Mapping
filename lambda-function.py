import json
import os
import uuid
from datetime import datetime, timezone, timedelta

import boto3
from botocore.exceptions import ClientError

# Core AWS clients
s3 = boto3.client("s3")
dynamodb = boto3.client("dynamodb")
sns = boto3.client("sns")
cloudtrail = boto3.client("cloudtrail")

# Bedrock client – Nova is hosted in us-east-1
bedrock = boto3.client(
    "bedrock-runtime",
    region_name=os.environ.get("BEDROCK_REGION", "us-east-1"),
)

# Env vars from CloudFormation
REPORT_BUCKET = os.environ["REPORT_BUCKET"]
TABLE_NAME = os.environ["TABLE_NAME"]
TOPIC_ARN = os.environ["TOPIC_ARN"]
MODEL_ID = os.environ.get("MODEL_ID", "amazon.nova-lite-v1:0")

CONTROL_MAP = {
    "IAM": {
        "nist": ["AC-2", "AC-6", "AU-12", "SI-4"],
        "cis": ["4", "5", "16"],
    },
    "NETWORK": {
        "nist": ["SC-7", "SI-4"],
        "cis": ["12", "13"],
    },
    "DEFAULT": {
        "nist": ["AU-6", "SI-4"],
        "cis": ["4", "8"],
    },
}


def handler(event, context):
    print("Received event:", json.dumps(event, default=str))

    detail = event.get("detail", {})

    # Handle both formats: Security Hub batch (detail.findings[]) or direct GuardDuty finding
    findings = []
    if isinstance(detail.get("findings"), list) and detail["findings"]:
        findings = detail["findings"]
    elif detail.get("id") or detail.get("Id"):
        findings = [detail]

    if not findings:
        print("No findings in event after parsing.")
        return {"statusCode": 200, "body": json.dumps({"message": "No findings"})}

    finding = findings[0]

    finding_id = finding.get("Id") or finding.get("id", "unknown")
    finding_type = finding.get("Type") or finding.get("type", "unknown")
    severity = float(finding.get("Severity") or finding.get("severity", 0))
    account_id = finding.get("AccountId") or finding.get("accountId", "unknown")
    region = finding.get("Region") or finding.get("region", "unknown")

    incident_id = str(uuid.uuid4())

    # Map to control families
    category_key = classify_category(finding_type)
    mapped_controls = CONTROL_MAP.get(category_key, CONTROL_MAP["DEFAULT"])

    # Simple risk score to show prioritization logic
    risk_score = compute_risk_score(severity, category_key)

    # Light MITRE-style tagging by finding type
    mitre_mapping = map_to_mitre(finding_type)

    # CloudTrail events in the last hour, with throttling handling
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=1)

    try:
        ct_events = cloudtrail.lookup_events(
            StartTime=start_time,
            EndTime=end_time,
            MaxResults=20,
        )
        cloudtrail_events = ct_events.get("Events", [])
    except ClientError as e:
        if e.response["Error"]["Code"] == "ThrottlingException":
            print("CloudTrail throttled, continuing without event context.")
            cloudtrail_events = []
        else:
            raise

    prompt = build_prompt(
        finding=finding,
        cloudtrail_events=cloudtrail_events,
        mapped_controls=mapped_controls,
        risk_score=risk_score,
        mitre_mapping=mitre_mapping,
    )

    ai_summary = call_bedrock(prompt)
    created_at = datetime.now(timezone.utc).isoformat()

    # Build report object
    report = {
        "incidentId": incident_id,
        "findingId": finding_id,
        "findingType": finding_type,
        "severity": severity,
        "accountId": account_id,
        "region": region,
        "riskScore": risk_score,
        "mappedControls": mapped_controls,
        "mitreMapping": mitre_mapping,
        "guardDutyFinding": finding,
        "cloudTrailEvents": cloudtrail_events,
        "aiSummary": ai_summary,
        "createdAt": created_at,
    }

    # Store JSON report
    json_key = f"incidents/{incident_id}.json"
    s3.put_object(
        Bucket=REPORT_BUCKET,
        Key=json_key,
        Body=json.dumps(report, indent=2, default=str),
        ContentType="application/json",
    )

    # Store a simple HTML report for easier viewing
    html_key = f"incidents/{incident_id}.html"
    html_body = build_html_report(report)
    s3.put_object(
        Bucket=REPORT_BUCKET,
        Key=html_key,
        Body=html_body,
        ContentType="text/html; charset=utf-8",
    )

    # Shorten AI summary for email
    ai_preview = (ai_summary or "").strip()
    if len(ai_preview) > 600:
        ai_preview = ai_preview[:600] + "... [truncated]"

    # SNS notification
    short_id = incident_id[:8]
    subject = f"[Incident] {short_id} Sev {int(severity)}"

    message_lines = [
        "A new GuardDuty incident was processed.",
        "",
        f"Incident ID: {incident_id}",
        f"Finding ID: {finding_id}",
        f"Type: {finding_type}",
        f"Severity: {severity}",
        f"Risk Score: {risk_score} / 10",
        f"Account: {account_id}",
        f"Region: {region}",
        "",
        f"NIST 800-53: {', '.join(mapped_controls.get('nist', []))}",
        f"CIS Controls: {', '.join(mapped_controls.get('cis', []))}",
        "MITRE ATT&CK: " + "; ".join(mitre_mapping) if mitre_mapping else "MITRE ATT&CK: n/a",
        "",
        "Quick AI Summary:",
        ai_preview or "(no summary returned)",
        "",
        "S3 JSON report key:",
        f"  {json_key}",
        "S3 HTML report key:",
        f"  {html_key}",
    ]
    message = "\n".join(message_lines)

    sns.publish(
        TopicArn=TOPIC_ARN,
        Subject=subject,
        Message=message,
    )

    # Index record in DynamoDB
    dynamodb.put_item(
        TableName=TABLE_NAME,
        Item={
            "IncidentId": {"S": incident_id},
            "FindingId": {"S": finding_id},
            "Severity": {"N": str(severity)},
            "Region": {"S": region},
            "S3JsonKey": {"S": json_key},
            "S3HtmlKey": {"S": html_key},
            "RiskScore": {"N": str(risk_score)},
            "NistControls": {"S": ",".join(mapped_controls.get("nist", []))},
            "CisControls": {"S": ",".join(mapped_controls.get("cis", []))},
            "MitreTags": {"S": ",".join(mitre_mapping)},
            "CreatedAt": {"S": created_at},
        },
    )

    return {"statusCode": 200, "body": json.dumps({"incidentId": incident_id})}


def classify_category(finding_type: str) -> str:
    if not finding_type:
        return "DEFAULT"
    if "IAM" in finding_type:
        return "IAM"
    if any(x in finding_type for x in ["PortProbe", "Recon", "Backdoor", "Network"]):
        return "NETWORK"
    return "DEFAULT"


def compute_risk_score(severity: float, category: str) -> float:
    base = max(0.0, min(severity, 10.0))
    if category == "IAM":
        base += 1.5
    elif category == "NETWORK":
        base += 1.0
    return round(min(base, 10.0), 1)


def map_to_mitre(finding_type: str):
    if not finding_type:
        return []
    finding_type = finding_type.lower()
    tags = []

    if "backdoor" in finding_type or "c&c" in finding_type:
        tags.append("TA0011: Command and Control")
    if "privilege" in finding_type or "escalation" in finding_type:
        tags.append("TA0004: Privilege Escalation")
    if "portsweep" in finding_type or "recon" in finding_type or "portprobe" in finding_type:
        tags.append("TA0043: Reconnaissance")
    if "exfiltration" in finding_type:
        tags.append("TA0010: Exfiltration")

    return tags


def build_prompt(finding, cloudtrail_events, mapped_controls, risk_score, mitre_mapping):
    return (
        "You are assisting with a cloud security incident review.\n"
        "Based on the data below, produce:\n"
        "1) A short summary in 3–5 bullet points.\n"
        "2) A brief timeline of key actions.\n"
        "3) 3–5 specific remediation steps.\n"
        "4) A short note on how this ties to the listed NIST 800-53 and CIS controls "
        "and the MITRE ATT&CK tags.\n\n"
        f"Risk score (0–10): {risk_score}\n"
        f"Mapped NIST 800-53: {', '.join(mapped_controls.get('nist', []))}\n"
        f"Mapped CIS Controls: {', '.join(mapped_controls.get('cis', []))}\n"
        f"MITRE ATT&CK tags: {', '.join(mitre_mapping)}\n\n"
        "GuardDuty finding JSON:\n"
        f"{json.dumps(finding, indent=2, default=str)}\n\n"
        "Recent CloudTrail events (may be related):\n"
        f"{json.dumps(cloudtrail_events, indent=2, default=str)}\n"
    )


def call_bedrock(prompt: str) -> str:
    body = json.dumps(
        {
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"text": prompt},
                    ],
                }
            ],
            "inferenceConfig": {
                "maxTokens": 800,
                "temperature": 0.3,
                "topP": 0.9,
            },
        }
    )

    resp = bedrock.invoke_model(
        modelId=MODEL_ID,
        body=body,
        contentType="application/json",
        accept="application/json",
    )

    raw = resp["body"].read()
    try:
        resp_body = json.loads(raw)
    except json.JSONDecodeError:
        return raw.decode("utf-8", errors="ignore")

    # Try common Nova response shapes
    if isinstance(resp_body, dict):
        if "outputText" in resp_body:
            return resp_body.get("outputText", "")

        output = resp_body.get("output")
        if isinstance(output, dict):
            message = output.get("message", {})
            content = message.get("content", [])
            if content and isinstance(content[0], dict):
                text = content[0].get("text")
                if text:
                    return text

    return json.dumps(resp_body)


def build_html_report(report: dict) -> str:
    """Very simple HTML wrapper for the incident report."""
    incident_id = report.get("incidentId", "")
    title = f"GuardDuty Incident {incident_id}"
    ai_summary = report.get("aiSummary", "") or "(no summary)"
    severity = report.get("severity", "n/a")
    risk_score = report.get("riskScore", "n/a")
    nist = ", ".join(report.get("mappedControls", {}).get("nist", []))
    cis = ", ".join(report.get("mappedControls", {}).get("cis", []))
    mitre = ", ".join(report.get("mitreMapping", []))

    body = [
        "<!DOCTYPE html>",
        "<html>",
        "<head>",
        "<meta charset='utf-8' />",
        f"<title>{title}</title>",
        "<style>",
        "body { font-family: system-ui, -apple-system, BlinkMacSystemFont, sans-serif; padding: 16px; }",
        "pre { background: #f5f5f5; padding: 12px; border-radius: 4px; overflow-x: auto; }",
        "h1, h2, h3 { font-weight: 600; }",
        "</style>",
        "</head>",
        "<body>",
        f"<h1>{title}</h1>",
        f"<p><strong>Severity:</strong> {severity} &nbsp; "
        f"<strong>Risk score:</strong> {risk_score}</p>",
        f"<p><strong>NIST 800-53:</strong> {nist or 'n/a'}</p>",
        f"<p><strong>CIS Controls:</strong> {cis or 'n/a'}</p>",
        f"<p><strong>MITRE ATT&CK:</strong> {mitre or 'n/a'}</p>",
        "<h2>AI Summary</h2>",
        "<pre>",
        ai_summary,
        "</pre>",
        "<h2>Full JSON Report</h2>",
        "<pre>",
        json.dumps(report, indent=2, default=str),
        "</pre>",
        "</body>",
        "</html>",
    ]

    return "\n".join(body)