# DRISHTI AWS deployment

This directory deploys the existing FastAPI application as a Lambda behind API
Gateway HTTP API. It does not move, replace, or bypass DRISHTI: every action still
passes through `EnforcedToolGateway`, whose deterministic `ALLOW`, `REVIEW`, or
`BLOCK` decision is made before an adapter can execute.

## Prerequisites

- An AWS account and an AWS CLI v2 profile with permission to provision the listed
  CloudFormation resources.
- AWS SAM CLI.
- Python 3.12 (for SAM's Lambda build) and Python 3.11+ for local backend tests.

No AWS credentials, account IDs, API keys, or secret values belong in this
repository. Configure the AWS CLI profile outside the repository.

## Build and deploy

Run from this directory:

```bash
cd infra
sam build --template-file template.yaml
sam deploy --guided
```

During the guided deploy, supply an `Environment` such as `dev` or `prod` and set
`FrontendAllowedOrigins` to the comma-separated deployed React/Amplify origin(s),
for example `https://main.example.amplifyapp.com`. Do not use `*` for a production
frontend. SAM/CloudFormation generates table and bucket names, passes them to
Lambda as environment variables, and returns `ApiUrl` in the stack outputs.

To retrieve it later:

```bash
aws cloudformation describe-stacks --stack-name <stack-name> \
  --query "Stacks[0].Outputs[?OutputKey=='ApiUrl'].OutputValue" --output text
```

The API exposes the FastAPI routes through the proxy integration, including
`POST /api/actions/evaluate`, `GET /api/traces/{request_id}`, `POST
/api/demo/safe-invoice`, and `POST /api/demo/malicious-invoice`.

## Data and security roles

- **DynamoDB:** policies, immutable-style security event records, request-keyed
  attack traces, and action/audit records. `AttackTracesTable` has
  `request_id` as its partition key and timestamp sort key, so a trace lookup is
  a DynamoDB `Query`, not a scan.
- **S3:** private, encrypted, versioned `safe/`, `malicious/`, and `attack/`
  demo artifacts. Public access is blocked; Lambda is limited to those prefixes.
- **CloudWatch:** Lambda JSON logs, X-Ray tracing, and API access logs. Do not add
  credentials or sensitive action arguments to application logs.
- **IAM:** the Lambda role grants only the table operations, S3 object prefixes,
  and log delivery needed by this deployment. The unavoidable `CreateLogGroup`
  wildcard is documented in the template; it is required before the function log
  group exists.

## Local development remains local

Without `DRISHTI_STORAGE_BACKEND=dynamodb`, the API continues to use
`DRISHTI_AUDIT_PATH` and the existing JSONL `LocalAuditStore`. AWS sets the backend
explicitly to `dynamodb`; local commands and tests therefore need neither AWS
credentials nor a running DynamoDB service.

## Architecture

```text
User
  ↓
React / Amplify
  ↓
API Gateway (HTTP API, CORS)
  ↓
Lambda (FastAPI adapter)
  ↓
DRISHTI Runtime Enforcement ── ALLOW / REVIEW / BLOCK ──> Protected tool
  ↓                         (REVIEW/BLOCK never execute the tool)
DynamoDB (policies, events, traces, actions)   S3 (private artifacts)
  ↓
CloudWatch Logs / API access logs / X-Ray
       IAM least-privilege execution role
```
