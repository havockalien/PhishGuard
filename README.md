# NS Phase 1 - Phishing Detection Setup

This project contains:
- `eda.py`: exploratory data analysis for the phishing dataset
- `feature_extractor.py`: URL feature extraction pipeline (30 UCI-style features)
- `train_model.py`: lightweight ML training (Logistic Regression, Decision Tree, Random Forest)

## 1) Create and activate virtual environment

### PowerShell (Windows)

```powershell
c:/python313/python.exe -m venv .venv
.\.venv\Scripts\Activate.ps1
```

## 2) Install dependencies

```powershell
pip install -r requirements.txt
```

## 3) Prepare dataset path for EDA

`eda.py` expects dataset at `data/phishing.csv`.

If your file is at project root (`phishing.csv`), run:

```powershell
New-Item -ItemType Directory -Force data | Out-Null
Copy-Item phishing.csv data/phishing.csv -Force
```

## 4) Run EDA

```powershell
python eda.py
```

Generated plots are written to `outputs/`.

## 5) Run feature extraction demo

```powershell
python feature_extractor.py
```

## 6) Train lightweight ML models (Phase 3)

```powershell
python train_model.py
```

Artifacts are saved to `models/`:
- `logistic_regression.joblib`
- `decision_tree.joblib`
- `random_forest.joblib`
- `best_model.joblib`
- `metrics.json`

Optional ONNX export:

```powershell
pip install skl2onnx
python train_model.py
```

If available, `models/best_model.onnx` is generated automatically.

## 7) Run inference endpoints (Phase 4 Cloud API layer)

Start API server:

```powershell
set API_KEYS=dev-key
set REQUIRE_API_KEY=true
set RATE_LIMIT_PER_MINUTE=60
python -m uvicorn inference_api:app --reload --port 8000
```

Available endpoints:
- `GET /health`
- `POST /predict` (simple contract)
- `POST /predict/url`
- `POST /predict/features`
- `POST /predict/batch`

Examples:

```powershell
# Health
Invoke-RestMethod -Uri http://127.0.0.1:8000/health -Method Get

# Predict using simple Phase 4 contract
$body = @{ url = "http://example.com" } | ConvertTo-Json
Invoke-RestMethod -Uri http://127.0.0.1:8000/predict -Method Post -Headers @{"x-api-key"="dev-key"} -ContentType "application/json" -Body $body

# Predict from URL (extended endpoint)
$body = @{ url = "https://github.com"; backend = "sklearn"; fetch_page = $false } | ConvertTo-Json
Invoke-RestMethod -Uri http://127.0.0.1:8000/predict/url -Method Post -Headers @{"x-api-key"="dev-key"} -ContentType "application/json" -Body $body

# Predict from features (model column names)
$body = @{ backend = "sklearn"; features = @{ UsingIP = 1; LongURL = 1; ShortURL = 1; "Symbol@" = 1; "Redirecting//" = 1; "PrefixSuffix-" = 1; SubDomains = 1; HTTPS = 1; DomainRegLen = 1; Favicon = 1; NonStdPort = 1; HTTPSDomainURL = 1; RequestURL = 1; AnchorURL = 1; LinksInScriptTags = 1; ServerFormHandler = 1; InfoEmail = 1; AbnormalURL = 1; WebsiteForwarding = 1; StatusBarCust = 1; DisableRightClick = 1; UsingPopupWindow = 1; IframeRedirection = 1; AgeofDomain = 1; DNSRecording = 1; WebsiteTraffic = 1; PageRank = 1; GoogleIndex = 1; LinksPointingToPage = 1; StatsReport = 1 } } | ConvertTo-Json -Depth 5
Invoke-RestMethod -Uri http://127.0.0.1:8000/predict/features -Method Post -Headers @{"x-api-key"="dev-key"} -ContentType "application/json" -Body $body
```

`POST /predict` response shape:

```json
{ "label": "phishing", "confidence": 0.94 }
```

Auth and rate limiting:
- Send API key in header: `x-api-key`
- API keys come from `API_KEYS` env var (comma-separated)
- Rate limit is controlled by `RATE_LIMIT_PER_MINUTE` (per key or per client)

## 8) Containerize API with Docker

Build and run the FastAPI container:

```powershell
docker build -t phishing-api:latest .
docker run --rm -p 8000:8000 -e API_KEYS=dev-key -e REQUIRE_API_KEY=true -e RATE_LIMIT_PER_MINUTE=60 phishing-api:latest
```

## 9) Deploy to AWS Lambda (container image)

Prerequisites:
- AWS CLI configured (`aws configure`)
- Docker running
- IAM role for Lambda with trust policy `lambda.amazonaws.com` and at least:
	- `AWSLambdaBasicExecutionRole`
	- ECR pull permission for Lambda runtime

One-command deployment (build image, push to ECR, create/update Lambda, wire API Gateway HTTP API):

```powershell
.\deploy_lambda.ps1 -Region ap-south-1 -RoleArn arn:aws:iam::216102776638:role/lambda-exec-role
```

Deploy with Phase 5 variables in one command (MongoDB + SMTP + PDF dir):

```powershell
$smtpPassword = ConvertTo-SecureString "your_app_password" -AsPlainText -Force
$smtpCredential = New-Object System.Management.Automation.PSCredential("your_email@example.com", $smtpPassword)

.\deploy_lambda.ps1 `
	-Region ap-south-1 `
	-RoleArn arn:aws:iam::216102776638:role/lambda-exec-role `
	-ApiKeys dev-key `
	-RequireApiKey true `
	-RateLimitPerMinute 60 `
	-MongodbUri "mongodb+srv://<user>:<password>@<cluster>/<db>?retryWrites=true&w=majority" `
	-MongodbDb phishing_detection `
	-MongodbCollection threat_events `
	-SmtpHost smtp.gmail.com `
	-SmtpPort 587 `
	-SmtpCredential $smtpCredential `
	-SmtpFrom your_email@example.com `
	-SmtpTo security-team@example.com `
	-SmtpUseStarttls true `
	-ReportsDir /tmp/reports
```

Optional flags:
- `-RepositoryName phishing-api-lambda`
- `-FunctionName phishing-api`
- `-ApiName phishing-api-http`
- `-ApiKeys dev-key`
- `-RateLimitPerMinute 60`
- `-MongodbUri <atlas-uri>`
- `-MongodbDb phishing_detection`
- `-MongodbCollection threat_events`
- `-SmtpHost smtp.gmail.com`
- `-SmtpPort 587`
- `-SmtpUser <email>`
- `-SmtpPassword <app-password>`
- `-SmtpFrom <email>`
- `-SmtpTo <recipient1,recipient2>`
- `-SmtpUseStarttls true`
- `-ReportsDir /tmp/reports`

Manual Lambda image build only:

```powershell
docker build -f Dockerfile.lambda -t phishing-api-lambda:latest .
```

Lambda handler entrypoint is `app_lambda.handler` (Mangum adapter).

## 10) Phase 5 - Automated threat reporting

When a phishing URL is detected (`label = phishing`), the API now:
- logs event to MongoDB Atlas
- sends email alert via `smtplib`
- generates a PDF report via `fpdf2`

Configure environment variables before running the API:

```powershell
# MongoDB Atlas
set MONGODB_URI=mongodb+srv://<user>:<password>@<cluster>/<db>?retryWrites=true&w=majority
set MONGODB_DB=phishing_detection
set MONGODB_COLLECTION=threat_events

# SMTP
set SMTP_HOST=smtp.gmail.com
set SMTP_PORT=587
set SMTP_USER=your_email@example.com
set SMTP_PASSWORD=your_app_password
set SMTP_FROM=your_email@example.com
set SMTP_TO=security-team@example.com
set SMTP_USE_STARTTLS=true

# Optional PDF output directory
set REPORTS_DIR=outputs/reports

# Optional TLS debug flag for MongoDB Atlas connectivity issues
# (Use only for debugging in restricted networks, keep false in production)
set MONGODB_TLS_ALLOW_INVALID=false
```

Run API:

```powershell
python -m uvicorn inference_api:app --reload --port 8000
```

On phishing detections, response includes `threat_reporting` with status for each step.

## 11) Streamlit dashboard

Start the dashboard:

```powershell
streamlit run dashboard.py
```

Dashboard includes:
- event counts and unique URLs
- source and timeline charts from MongoDB Atlas
- recent detection table
- generated PDF report listing from `outputs/reports`

## 12) Deploy Streamlit to AWS (App Runner)

This deploys your Streamlit UI as a public web app on AWS.

### Prerequisite: App Runner ECR access role (one-time)

Create an IAM role trusted by `build.apprunner.amazonaws.com` and attach policy:
- `AWSAppRunnerServicePolicyForECRAccess`

Save the role ARN (example):
- `arn:aws:iam::216102776638:role/AppRunnerEcrAccessRole`

### Deploy command

```powershell
$region = "ap-south-1"
$appRunnerAccessRoleArn = "arn:aws:iam::216102776638:role/AppRunnerEcrAccessRole"

.\deploy_streamlit.ps1 `
	-Region $region `
	-AccessRoleArn $appRunnerAccessRoleArn `
	-RepositoryName "phishing-dashboard" `
	-ServiceName "phishing-dashboard" `
	-ApiBaseUrl "https://dcfj0ukd69.execute-api.ap-south-1.amazonaws.com" `
	-DashboardApiKey "dev-key" `
	-MongodbUri "mongodb+srv://<user>:<password>@<cluster>/<db>?retryWrites=true&w=majority" `
	-MongodbDb "phishing_detection" `
	-MongodbCollection "threat_events"
```

The script prints:
- App Runner service ARN
- public Streamlit URL

If status is still deploying, wait 2-5 minutes and refresh the URL.

## Notes

- Some feature checks use network and SSL and may be affected by connectivity.
- WHOIS-dependent features need `python-whois` and may still return neutral values on lookup failures.
- TFLite export is not direct from scikit-learn models; ONNX is the lightweight deployment format used here.
 