# PhishGuard

PhishGuard is a phishing URL detection system with:
- FastAPI inference API
- automated threat reporting (MongoDB Atlas, email alert, PDF generation)
- optional S3 PDF upload with presigned download URL
- Streamlit dashboard (end-user scanner + analyst view)
- AWS deployment scripts for Lambda/API Gateway and Streamlit container hosting

## Project structure

- `inference_api.py`: API endpoints and prediction flow
- `feature_extractor.py`: URL feature engineering
- `train_model.py`: model training and artifact export
- `reporting.py`: Mongo/email/PDF/S3 reporting pipeline
- `dashboard.py`: Streamlit dashboard app
- `app_lambda.py`: Lambda entrypoint via Mangum
- `deploy_lambda.ps1`: deploy API container to AWS Lambda + API Gateway
- `deploy_streamlit.ps1`: deploy Streamlit container to AWS App Runner (if available)
- `Dockerfile`: local API container
- `Dockerfile.lambda`: Lambda image build
- `Dockerfile.streamlit`: dashboard image build

## 1. Local quick start

### Prerequisites

- Python 3.10+
- Docker Desktop
- AWS CLI configured (for cloud steps)

### Setup virtual environment

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### Train or reuse models

Models already exist in `models/`. To retrain:

```powershell
python train_model.py
```

## 2. Run API locally

### Minimum environment

```powershell
$env:API_KEYS = "dev-key"
$env:REQUIRE_API_KEY = "true"
$env:RATE_LIMIT_PER_MINUTE = "60"
```

### Reporting environment (Phase 5)

```powershell
# MongoDB Atlas
$env:MONGODB_URI = "mongodb+srv://<user>:<password>@<cluster>/<db>?retryWrites=true&w=majority"
$env:MONGODB_DB = "phishing_detection"
$env:MONGODB_COLLECTION = "threat_events"

# SMTP
$env:SMTP_HOST = "smtp.gmail.com"
$env:SMTP_PORT = "587"
$env:SMTP_USER = "your_email@example.com"
$env:SMTP_PASSWORD = "your_app_password"
$env:SMTP_FROM = "your_email@example.com"
$env:SMTP_TO = "security-team@example.com"
$env:SMTP_USE_STARTTLS = "true"

# PDF output
$env:REPORTS_DIR = "outputs/reports"

# Optional S3 upload for PDFs
$env:REPORTS_S3_BUCKET = "your-s3-bucket-name"
$env:REPORTS_S3_PREFIX = "reports/"
$env:REPORTS_S3_REGION = "ap-south-1"
$env:REPORTS_S3_PRESIGNED_EXPIRY = "3600"

# Optional Mongo TLS override for debugging only
$env:MONGODB_TLS_ALLOW_INVALID = "false"
```

### Start API

```powershell
python -m uvicorn inference_api:app --reload --port 8000
```

### Verify API quickly

```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8000/health" -Method Get

$body = @{ url = "http://example.com" } | ConvertTo-Json
Invoke-RestMethod -Uri "http://127.0.0.1:8000/predict" -Method Post -Headers @{"x-api-key"="dev-key"} -ContentType "application/json" -Body $body
```

## 3. Run Streamlit locally

In a second terminal:

```powershell
$env:API_BASE_URL = "http://127.0.0.1:8000"
$env:DASHBOARD_API_KEY = "dev-key"
$env:SCANNER_TIMEOUT_SECONDS = "60"
streamlit run dashboard.py
```

Open `http://localhost:8501`.

## 4. Run with Docker locally

### API container

```powershell
docker build -t phishing-api:latest .
docker run --rm -p 8000:8000 `
	-e API_KEYS=dev-key `
	-e REQUIRE_API_KEY=true `
	-e RATE_LIMIT_PER_MINUTE=60 `
	phishing-api:latest
```

### Streamlit container

```powershell
docker build -f Dockerfile.streamlit -t phishing-dashboard:latest .
docker run --rm -p 8501:8501 `
	-e API_BASE_URL=http://host.docker.internal:8000 `
	-e DASHBOARD_API_KEY=dev-key `
	phishing-dashboard:latest
```

## 5. Deploy API to AWS Lambda + API Gateway

### Prerequisites

- ECR access in your AWS account
- Lambda execution role (example: `lambda-exec-role`) with:
	- CloudWatch Logs permissions (`AWSLambdaBasicExecutionRole`)
	- permission to pull from ECR

### Deploy command

```powershell
$smtpPassword = ConvertTo-SecureString "your_app_password" -AsPlainText -Force
$smtpCredential = New-Object System.Management.Automation.PSCredential("your_email@example.com", $smtpPassword)

.\deploy_lambda.ps1 `
	-Region ap-south-1 `
	-RoleArn arn:aws:iam::216102776638:role/lambda-exec-role `
	-ApiKeys "dev-key" `
	-RequireApiKey $true `
	-RateLimitPerMinute 60 `
	-MongodbUri "mongodb+srv://<user>:<password>@<cluster>/<db>?retryWrites=true&w=majority" `
	-MongodbDb "phishing_detection" `
	-MongodbCollection "threat_events" `
	-SmtpHost "smtp.gmail.com" `
	-SmtpPort 587 `
	-SmtpCredential $smtpCredential `
	-SmtpFrom "your_email@example.com" `
	-SmtpTo "security-team@example.com" `
	-SmtpUseStarttls $true `
	-ReportsDir "/tmp/reports" `
	-ReportsS3Bucket "your-s3-bucket-name" `
	-ReportsS3Prefix "reports/" `
	-ReportsS3Region "ap-south-1" `
	-ReportsS3PresignedExpiry 3600
```

The script builds and pushes image, creates/updates Lambda, and configures API Gateway.

## 6. Deploy Streamlit to cloud

### Option A: App Runner (if your AWS account supports it)

```powershell
.\deploy_streamlit.ps1 `
	-Region ap-south-1 `
	-AccessRoleArn arn:aws:iam::216102776638:role/AppRunnerEcrAccessRole `
	-RepositoryName "phishing-dashboard" `
	-ServiceName "phishing-dashboard" `
	-ApiBaseUrl "https://<your-api-id>.execute-api.ap-south-1.amazonaws.com" `
	-DashboardApiKey "dev-key" `
	-MongodbUri "mongodb+srv://<user>:<password>@<cluster>/<db>?retryWrites=true&w=majority" `
	-MongodbDb "phishing_detection" `
	-MongodbCollection "threat_events"
```

### Option B: EC2 Docker deployment (recommended fallback)

Run this from your local PowerShell (not from inside EC2 shell):

```powershell
$region = "ap-south-1"
$dashboardImage = "216102776638.dkr.ecr.$region.amazonaws.com/phishing-dashboard:latest"
$apiBaseUrl = "https://<your-api-id>.execute-api.ap-south-1.amazonaws.com"
$newApiKey = "<your-api-key>"
$newMongoUri = "mongodb+srv://<user>:<password>@<cluster>/<db>?retryWrites=true&w=majority"
$keyPath = "C:\path\to\your\ec2-key.pem"
$ec2Host = "<your-ec2-public-ip>"

$ec2Cmd = @"
set -e
aws ecr get-login-password --region $region | docker login --username AWS --password-stdin 216102776638.dkr.ecr.$region.amazonaws.com >/dev/null
docker pull $dashboardImage >/dev/null
docker rm -f phishing-dashboard >/dev/null 2>&1 || true
docker run -d --name phishing-dashboard -p 8501:8501 \
	-e API_BASE_URL='$apiBaseUrl' \
	-e DASHBOARD_API_KEY='$newApiKey' \
	-e SCANNER_TIMEOUT_SECONDS='60' \
	-e MONGODB_URI='$newMongoUri' \
	-e MONGODB_DB='phishing_detection' \
	-e MONGODB_COLLECTION='threat_events' \
	$dashboardImage >/dev/null
docker ps --filter name=phishing-dashboard
docker logs phishing-dashboard --tail 25
"@

ssh -i "$keyPath" ec2-user@$ec2Host "$ec2Cmd"
```

## 7. Push project to GitHub

If your remote is already configured:

```powershell
git status
git add .
git commit -m "Finalize phishing detection platform"
git push -u origin main
```

If remote is not configured yet:

```powershell
git remote add origin https://github.com/<your-user>/<your-repo>.git
git branch -M main
git push -u origin main
```

## 8. Security and key rotation

When rotating API key (`dev-key` -> new key):

1. Update Lambda `API_KEYS` using `deploy_lambda.ps1` with new value.
2. Redeploy EC2 Streamlit container with `DASHBOARD_API_KEY` set to new key.
3. Update all clients using header `x-api-key`.
4. Verify old key returns `401`, new key returns success.

Also rotate leaked values immediately:

- MongoDB credentials
- SMTP app password
- any AWS IAM keys

## 9. Operational checks

### API health

```powershell
Invoke-RestMethod -Uri "https://<your-api-id>.execute-api.ap-south-1.amazonaws.com/health" -Method Get
```

### Trigger a scan

```powershell
$body = @{ url = "https://example.com" } | ConvertTo-Json
Invoke-RestMethod -Uri "https://<your-api-id>.execute-api.ap-south-1.amazonaws.com/predict" -Method Post -Headers @{"x-api-key"="<your-api-key>"} -ContentType "application/json" -Body $body
```

### What success looks like

- API returns prediction JSON
- `threat_reporting.mongodb.ok` is true for phishing events
- `threat_reporting.email.ok` is true (if SMTP configured)
- `threat_reporting.pdf.ok` is true
- when S3 is configured, `threat_reporting.pdf.download_url` is present

## 10. Troubleshooting

- `MongoDB logging failed`
	- verify `MONGODB_URI`, Atlas Network Access, DB user permissions
	- ensure Lambda/EC2 outbound access to Atlas
- `Email failed`
	- verify `SMTP_*` values and app password
- `503` or timeout on deep scan
	- increase `SCANNER_TIMEOUT_SECONDS` or use non-deep scan path
- `SignatureDoesNotMatch` for PDF URL
	- verify `REPORTS_S3_REGION` matches bucket region
- dashboard shows stale or empty data
	- restart dashboard container and verify `MONGODB_*` env vars

## 11. Notes

- Local PDF reports are written under `outputs/reports`.
- In Lambda, local storage is ephemeral, so S3 upload is strongly recommended.
- See `OPERATIONS.md` for additional deployment and maintenance commands.
 