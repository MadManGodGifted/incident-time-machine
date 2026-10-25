# AWS Lambda Deployment Guide: Incident Time Machine

This guide details how to package and deploy the deterministic Incident Time Machine engine to **AWS Lambda** for use as a standalone microservice, API Gateway backend, or an Amazon Bedrock Agent Action Group tool.

---

## 1. Runtime Specifications

| Configuration Item | Recommended Value | Notes |
| :--- | :--- | :--- |
| **Runtime** | `Python 3.12` (or `Python 3.11`) | Standard AWS Lambda managed runtime. |
| **Handler** | `lambda_function.lambda_handler` | Root entrypoint delegating to `src.incident_time_machine.lambda_handler`. |
| **Architecture** | `arm64` (AWS Graviton) or `x86_64` | `arm64` is recommended for lower latency and reduced cost. |
| **Memory** | `256 MB` | Pure in-memory chronological sorting and trace correlation. |
| **Timeout** | `15 - 30 seconds` | Sufficient for sorting up to 100,000+ log lines. |
| **Ephemeral Storage (`/tmp`)** | `512 MB` (Default) | No local disk writes required by the engine. |
| **Environment Variables** | None required | The deterministic engine has zero credential requirements. |

---

## 2. Package Structure & Zero-Dependency Advantage

The deterministic Lambda handler depends **exclusively on the Python standard library** (`dataclasses`, `datetime`, `json`, `enum`, `typing`, `base64`). 

> **Important**: You do **NOT** need to package `strands-agents`, `boto3`, or any external pip dependencies into the Lambda zip. The Lambda package is ultra-lightweight (under 50 KB).

### Zip Archive Structure
```text
incident_time_machine_lambda.zip
├── lambda_function.py
└── src/
    └── incident_time_machine/
        ├── __init__.py
        ├── lambda_handler.py
        ├── engine.py
        ├── models.py
        ├── parser.py
        └── prompts.py
```

---

## 3. Creating the Deployment Package

Run the following command locally in PowerShell or Bash to create the deployment archive:

### Windows PowerShell:
```powershell
Compress-Archive -Path "lambda_function.py", "src" -DestinationPath "incident_time_machine_lambda.zip" -Force
```

### Linux / macOS:
```bash
zip -r incident_time_machine_lambda.zip lambda_function.py src/ -x "src/**/__pycache__/*"
```

---

## 4. AWS Console Configuration

1. **Create Function**:
   - Navigate to the **AWS Lambda Console** $\rightarrow$ **Create function**.
   - Select **Author from scratch**.
   - Function name: `incident-time-machine-engine`.
   - Runtime: `Python 3.12`.
   - Architecture: `arm64` (or `x86_64`).
2. **Upload Code**:
   - In the **Code source** section, click **Upload from** $\rightarrow$ **.zip file**.
   - Select `incident_time_machine_lambda.zip`.
3. **Configure Runtime Settings**:
   - Under **Runtime settings**, click **Edit**.
   - Handler: `lambda_function.lambda_handler`.
   - Save changes.
4. **General Configuration**:
   - Go to **Configuration** $\rightarrow$ **General configuration** $\rightarrow$ **Edit**.
   - Memory: `256 MB`.
   - Timeout: `30 sec`.

---

## 5. Supported Invocation Envelopes

The Lambda handler automatically detects and normalizes requests across three calling patterns:

### Pattern A: Direct Lambda Invocation (`lambda:Invoke`)
Payload:
```json
{
  "logs": [
    {
      "timestamp": "2026-10-25T08:14:15.200Z",
      "service": "inventory-service",
      "level": "ERROR",
      "message": "Connection pool exhausted",
      "request_id": "req-101"
    }
  ]
}
```

### Pattern B: Amazon API Gateway / Function URL (HTTP POST)
Payload forwarded by API Gateway with stringified JSON in `body`:
```json
{
  "resource": "/analyze",
  "httpMethod": "POST",
  "headers": {"Content-Type": "application/json"},
  "body": "{\"logs\": [...]}",
  "isBase64Encoded": false
}
```

### Pattern C: Amazon Bedrock Agent Action Group
Event envelope dispatched by an Amazon Bedrock Agent:
```json
{
  "actionGroup": "IncidentTimeMachineGroup",
  "apiPath": "/analyze",
  "httpMethod": "POST",
  "requestBody": {
    "content": {
      "application/json": {
        "properties": [
          {
            "name": "logs",
            "type": "array",
            "value": "[...]"
          }
        ]
      }
    }
  }
}
```

---

## 6. Response Contract

### Success Response (`200 OK`)
```json
{
  "statusCode": 200,
  "headers": {"Content-Type": "application/json"},
  "body": "{\"status\": \"success\", \"report\": {...}}",
  "status": "success",
  "report": {
    "timeline": [
      {
        "event_id": "evt-0001",
        "timestamp": "2026-10-25T08:14:05+00:00",
        "timestamp_iso": "2026-10-25T08:14:05.000Z",
        "service": "telemetry-collector",
        "level": "INFO",
        "message": "Periodic agent heartbeat ok",
        "request_id": null,
        "metadata": {}
      }
    ],
    "traces": {
      "req-101": {
        "request_id": "req-101",
        "event_ids": ["evt-0002", "evt-0005"],
        "services": ["api-gateway", "inventory-service"],
        "has_error": true
      }
    },
    "earliest_recorded_error": {
      "event_id": "evt-0005",
      "service": "inventory-service",
      "level": "ERROR"
    },
    "hypotheses": [
      {
        "hypothesis_id": "hyp-01",
        "claim": "Earliest recorded error manifested in service 'inventory-service'...",
        "evidence_event_ids": ["evt-0005"],
        "confidence": "MEDIUM",
        "uncertainties": [
          "CAUSATION DISCLAIMER: Chronological precedence does NOT prove causation."
        ]
      }
    ],
    "unknowns": [
      "Underlying host/container health metrics are absent."
    ],
    "validation_errors": []
  }
}
```

### Error Response (`400 Bad Request`)
```json
{
  "statusCode": 400,
  "headers": {"Content-Type": "application/json"},
  "body": "{\"error_code\": \"BAD_REQUEST\", \"message\": \"Field 'logs' must be a list of log records.\"}",
  "error": {
    "error_code": "BAD_REQUEST",
    "message": "Field 'logs' must be a list of log records."
  }
}
```

---

## 7. Connecting Local Strands Agent to Deployed Lambda

The local Strands Agent integrates directly with the deployed AWS Lambda function using the custom tool `invoke_lambda_incident_analysis` via `boto3`.

### Configuration Details
- **Function Name**: `incident-time-machine`
- **Region**: `ap-southeast-2` (Sydney)
- **Invocation Type**: `RequestResponse`

### Minimum IAM Permissions (Least-Privilege)
To permit the local Strands agent to invoke the deployed function, attach this policy to the local IAM user or execution role:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "InvokeIncidentTimeMachineOnly",
      "Effect": "Allow",
      "Action": "lambda:InvokeFunction",
      "Resource": "arn:aws:lambda:ap-southeast-2:*:function:incident-time-machine"
    }
  ]
}
```

### Local AWS Credentials Setup
Set up credentials using either standard method:
1. **AWS CLI Configuration**:
   ```bash
   aws configure
   # Set Default region name: ap-southeast-2
   ```
2. **Environment Variables**:
   ```bash
   export AWS_ACCESS_KEY_ID="your-access-key-id"
   export AWS_SECRET_ACCESS_KEY="your-secret-access-key"
   export AWS_DEFAULT_REGION="ap-southeast-2"
   ```

### Execution Example
```bash
# Run the Strands agent in remote Lambda mode
python -m src.incident_time_machine.agent_cli incident_out_of_order.json --remote-lambda
```
If AWS credentials are not configured, the tool safely catches `botocore.exceptions.NoCredentialsError` and returns:
```json
{
  "status": "error",
  "error_code": "NO_CREDENTIALS",
  "message": "AWS credentials not configured. Please configure an AWS profile or set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY with 'lambda:InvokeFunction' permission for function 'incident-time-machine' in region 'ap-southeast-2'."
}
```
