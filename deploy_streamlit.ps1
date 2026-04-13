param(
    [Parameter(Mandatory = $true)]
    [string]$Region,

    [Parameter(Mandatory = $true)]
    [string]$AccessRoleArn,

    [string]$RepositoryName = "phishing-dashboard",
    [string]$ServiceName = "phishing-dashboard",
    [string]$ImageTag = "latest",

    [string]$ApiBaseUrl = "",
    [string]$DashboardApiKey = "dev-key",

    [string]$MongodbUri = "",
    [string]$MongodbDb = "phishing_detection",
    [string]$MongodbCollection = "threat_events"
)

$ErrorActionPreference = "Stop"
# In some PowerShell hosts, native command non-zero exits become terminating
# errors before we can inspect $LASTEXITCODE and stderr.
$PSNativeCommandUseErrorActionPreference = $false

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Step,
        [Parameter(Mandatory = $true)]
        [scriptblock]$Command
    )

    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $output = & $Command 2>&1
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $prevEap
    }
    if ($code -ne 0) {
        $text = ($output | Out-String).Trim()
        throw "[$Step] failed (exit code $code).`n$text"
    }
    return $output
}

Write-Host "[1/7] Validating tooling..."
Invoke-Checked -Step "aws --version" -Command { aws --version | Out-Null } | Out-Null
Invoke-Checked -Step "docker --version" -Command { docker --version | Out-Null } | Out-Null

Write-Host "[2/7] Getting AWS account id..."
$AccountId = (Invoke-Checked -Step "sts get-caller-identity" -Command {
    aws sts get-caller-identity --query Account --output text
} | Out-String).Trim()
if (-not $AccountId) {
    throw "Failed to resolve AWS account id. Ensure AWS CLI is configured (aws configure)."
}

$EcrUri = "$AccountId.dkr.ecr.$Region.amazonaws.com"
$ImageUri = "$EcrUri/${RepositoryName}:$ImageTag"

Write-Host "[3/7] Ensuring ECR repository exists..."
$repoExists = $true
$repoCheck = aws ecr describe-repositories --repository-names $RepositoryName --region $Region 2>&1
if ($LASTEXITCODE -ne 0) {
    $repoCheckText = ($repoCheck | Out-String)
    if ($repoCheckText -match "RepositoryNotFoundException") {
        $repoExists = $false
    } else {
        throw "[ecr describe-repositories] failed.`n$repoCheckText"
    }
}
if (-not $repoExists) {
    Invoke-Checked -Step "ecr create-repository" -Command {
        aws ecr create-repository --repository-name $RepositoryName --region $Region | Out-Null
    } | Out-Null
}

Write-Host "[4/7] Logging in to ECR..."
$loginPassword = (Invoke-Checked -Step "ecr get-login-password" -Command {
    aws ecr get-login-password --region $Region
} | Out-String).Trim()
$loginPassword | docker login --username AWS --password-stdin $EcrUri | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "[docker login] failed."
}

Write-Host "[5/7] Building and pushing Streamlit image..."
docker build --platform linux/amd64 --provenance=false --sbom=false -f Dockerfile.streamlit -t "${RepositoryName}:$ImageTag" .
if ($LASTEXITCODE -ne 0) {
    throw "[docker build] failed."
}

docker tag "${RepositoryName}:$ImageTag" $ImageUri
if ($LASTEXITCODE -ne 0) {
    throw "[docker tag] failed."
}

docker push $ImageUri
if ($LASTEXITCODE -ne 0) {
    throw "[docker push] failed."
}

Write-Host "[6/7] Creating or updating App Runner service..."
$envVars = [ordered]@{
    API_BASE_URL = $ApiBaseUrl
    DASHBOARD_API_KEY = $DashboardApiKey
    MONGODB_URI = $MongodbUri
    MONGODB_DB = $MongodbDb
    MONGODB_COLLECTION = $MongodbCollection
}

$sourceConfig = @{
    AuthenticationConfiguration = @{ AccessRoleArn = $AccessRoleArn }
    AutoDeploymentsEnabled = $false
    ImageRepository = @{
        ImageIdentifier = $ImageUri
        ImageRepositoryType = "ECR"
        ImageConfiguration = @{
            Port = "8501"
            RuntimeEnvironmentVariables = $envVars
        }
    }
}

$tmpSourceConfigPath = Join-Path $env:TEMP "apprunner-source-$ServiceName.json"
$sourceConfig | ConvertTo-Json -Depth 8 | Set-Content -Path $tmpSourceConfigPath -Encoding ascii

$ServiceArn = (Invoke-Checked -Step "apprunner list-services" -Command {
    aws apprunner list-services --region $Region --query "ServiceSummaryList[?ServiceName=='$ServiceName'].ServiceArn | [0]" --output text
} | Out-String).Trim()

if (-not $ServiceArn -or $ServiceArn -eq "None") {
    $createResult = Invoke-Checked -Step "apprunner create-service" -Command {
        aws apprunner create-service `
            --service-name $ServiceName `
            --source-configuration file://$tmpSourceConfigPath `
            --instance-configuration Cpu=1024,Memory=2048 `
            --region $Region
    }
    $ServiceArn = (($createResult | Out-String) | ConvertFrom-Json).Service.ServiceArn
} else {
    Invoke-Checked -Step "apprunner update-service" -Command {
        aws apprunner update-service `
            --service-arn $ServiceArn `
            --source-configuration file://$tmpSourceConfigPath `
            --region $Region | Out-Null
    } | Out-Null
}

Remove-Item -Path $tmpSourceConfigPath -Force -ErrorAction SilentlyContinue

Write-Host "[7/7] Fetching service URL..."
$ServiceUrl = (Invoke-Checked -Step "apprunner describe-service" -Command {
    aws apprunner describe-service --service-arn $ServiceArn --region $Region --query "Service.ServiceUrl" --output text
} | Out-String).Trim()

Write-Host "Done."
Write-Host "App Runner service ARN: $ServiceArn"
Write-Host "Streamlit URL: https://$ServiceUrl"
Write-Host ""
Write-Host "If service is still deploying, wait 2-5 minutes and refresh the URL."
