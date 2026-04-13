param(
    [Parameter(Mandatory = $true)]
    [string]$Region,

    [Parameter(Mandatory = $true)]
    [string]$RoleArn,

    [string]$RepositoryName = "phishing-api-lambda",
    [string]$FunctionName = "phishing-api",
    [string]$ApiName = "phishing-api-http",
    [string]$ImageTag = "latest",
    [int]$MemorySize = 1024,
    [int]$TimeoutSeconds = 30,
    [string]$ApiKeys = "dev-key",
    [string]$RequireApiKey = "true",
    [string]$RateLimitPerMinute = "60",

    [string]$MongodbUri = "",
    [string]$MongodbDb = "phishing_detection",
    [string]$MongodbCollection = "threat_events",

    [string]$SmtpHost = "",
    [string]$SmtpPort = "587",
    [string]$SmtpUser = "",
    [System.Management.Automation.PSCredential]$SmtpCredential = $null,
    [string]$SmtpFrom = "",
    [string]$SmtpTo = "",
    [string]$SmtpUseStarttls = "true",

    [string]$ReportsDir = "/tmp/reports"
)

$ErrorActionPreference = "Continue"

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Step,
        [Parameter(Mandatory = $true)]
        [scriptblock]$Command
    )

    $output = & $Command 2>&1
    $code = $LASTEXITCODE
    if ($code -ne 0) {
        $text = ($output | Out-String).Trim()
        throw "[$Step] failed (exit code $code).`n$text"
    }
    return $output
}

function Wait-LambdaReady {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FunctionName,
        [Parameter(Mandatory = $true)]
        [string]$Region
    )
    # Avoid requiring lambda:GetFunctionConfiguration; give Lambda time to settle.
    Start-Sleep -Seconds 15
}

function Get-LambdaEnvironmentFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $smtpUserValue = $SmtpUser
    $smtpPasswordPlain = ""
    if ($null -ne $SmtpCredential) {
        if (-not $smtpUserValue) {
            $smtpUserValue = $SmtpCredential.UserName
        }
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SmtpCredential.Password)
        try {
            $smtpPasswordPlain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        } finally {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
    }

    $variables = [ordered]@{
        API_KEYS = $ApiKeys
        REQUIRE_API_KEY = $RequireApiKey
        RATE_LIMIT_PER_MINUTE = $RateLimitPerMinute
        MONGODB_URI = $MongodbUri
        MONGODB_DB = $MongodbDb
        MONGODB_COLLECTION = $MongodbCollection
        SMTP_HOST = $SmtpHost
        SMTP_PORT = $SmtpPort
        SMTP_USER = $smtpUserValue
        SMTP_PASSWORD = $smtpPasswordPlain
        SMTP_FROM = $SmtpFrom
        SMTP_TO = $SmtpTo
        SMTP_USE_STARTTLS = $SmtpUseStarttls
        REPORTS_DIR = $ReportsDir
    }

    $envPayload = @{
        Variables = $variables
    }

    $json = $envPayload | ConvertTo-Json -Depth 4
    Set-Content -Path $Path -Value $json -Encoding ascii
}

Write-Host "[1/9] Validating tooling..."
Invoke-Checked -Step "aws --version" -Command { aws --version | Out-Null } | Out-Null
Invoke-Checked -Step "docker --version" -Command { docker --version | Out-Null } | Out-Null

Write-Host "[2/9] Getting AWS account id..."
$AccountId = (Invoke-Checked -Step "sts get-caller-identity" -Command {
    aws sts get-caller-identity --query Account --output text
} | Out-String).Trim()
if (-not $AccountId) {
    throw "Failed to resolve AWS account id. Ensure AWS CLI is configured (aws configure)."
}

$EcrUri = "$AccountId.dkr.ecr.$Region.amazonaws.com"
$ImageUri = "$EcrUri/${RepositoryName}:$ImageTag"

Write-Host "[3/9] Ensuring ECR repository exists..."
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

Write-Host "[3.5/9] Ensuring ECR repository policy allows Lambda image pull..."
$ecrPolicy = @"
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowLambdaServicePull",
            "Effect": "Allow",
            "Principal": {
                "Service": "lambda.amazonaws.com"
            },
            "Action": [
                "ecr:BatchGetImage",
                "ecr:GetDownloadUrlForLayer"
            ],
            "Condition": {
                "StringLike": {
                    "aws:sourceArn": "arn:aws:lambda:${Region}:${AccountId}:function:*"
                }
            }
        },
        {
            "Sid": "AllowAccountRootPull",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::${AccountId}:root"
            },
            "Action": [
                "ecr:BatchGetImage",
                "ecr:GetDownloadUrlForLayer"
            ]
        }
    ]
}
"@
$tmpPolicyPath = Join-Path $env:TEMP "ecr-lambda-policy.json"
Set-Content -Path $tmpPolicyPath -Value $ecrPolicy -Encoding ascii
Invoke-Checked -Step "ecr set-repository-policy" -Command {
        aws ecr set-repository-policy --repository-name $RepositoryName --region $Region --policy-text file://$tmpPolicyPath | Out-Null
} | Out-Null
Remove-Item -Path $tmpPolicyPath -Force -ErrorAction SilentlyContinue

Write-Host "[4/9] Logging in to ECR..."
$loginPassword = (Invoke-Checked -Step "ecr get-login-password" -Command {
    aws ecr get-login-password --region $Region
} | Out-String).Trim()
$loginPassword | docker login --username AWS --password-stdin $EcrUri | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "[docker login] failed."
}

Write-Host "[5/9] Building Lambda container image..."
docker build --platform linux/amd64 --provenance=false --sbom=false -f Dockerfile.lambda -t "${RepositoryName}:$ImageTag" .
if ($LASTEXITCODE -ne 0) {
    throw "[docker build] failed."
}

Write-Host "[6/9] Tagging and pushing image..."
docker tag "${RepositoryName}:$ImageTag" $ImageUri
if ($LASTEXITCODE -ne 0) {
    throw "[docker tag] failed."
}
docker push $ImageUri
if ($LASTEXITCODE -ne 0) {
    throw "[docker push] failed."
}

Write-Host "[7/9] Creating or updating Lambda function..."
$tmpLambdaEnvPath = Join-Path $env:TEMP "lambda-env-$FunctionName.json"
Get-LambdaEnvironmentFile -Path $tmpLambdaEnvPath
$fnExists = $true
$fnCheck = aws lambda get-function --function-name $FunctionName --region $Region 2>&1
if ($LASTEXITCODE -ne 0) {
    $fnCheckText = ($fnCheck | Out-String)
    if ($fnCheckText -match "ResourceNotFoundException") {
        $fnExists = $false
    } else {
        throw "[lambda get-function] failed.`n$fnCheckText"
    }
}

if (-not $fnExists) {
    Invoke-Checked -Step "lambda create-function" -Command {
        aws lambda create-function `
            --function-name $FunctionName `
            --package-type Image `
            --code ImageUri=$ImageUri `
            --role $RoleArn `
            --memory-size $MemorySize `
            --timeout $TimeoutSeconds `
            --region $Region `
            --environment file://$tmpLambdaEnvPath | Out-Null
    } | Out-Null
    Wait-LambdaReady -FunctionName $FunctionName -Region $Region
} else {
    Invoke-Checked -Step "lambda update-function-code" -Command {
        aws lambda update-function-code `
            --function-name $FunctionName `
            --image-uri $ImageUri `
            --region $Region | Out-Null
    } | Out-Null
    Wait-LambdaReady -FunctionName $FunctionName -Region $Region

    $updated = $false
    for ($i = 0; $i -lt 3 -and -not $updated; $i++) {
        $cfg = aws lambda update-function-configuration `
            --function-name $FunctionName `
            --memory-size $MemorySize `
            --timeout $TimeoutSeconds `
            --region $Region `
            --environment file://$tmpLambdaEnvPath 2>&1
        if ($LASTEXITCODE -eq 0) {
            $updated = $true
            Wait-LambdaReady -FunctionName $FunctionName -Region $Region
        } else {
            $cfgText = ($cfg | Out-String)
            if ($cfgText -match "ResourceConflictException") {
                Start-Sleep -Seconds 10
                Wait-LambdaReady -FunctionName $FunctionName -Region $Region
            } else {
                throw "[lambda update-function-configuration] failed.`n$cfgText"
            }
        }
    }
    if (-not $updated) {
        throw "[lambda update-function-configuration] failed after retries due to ongoing updates."
    }
}
Remove-Item -Path $tmpLambdaEnvPath -Force -ErrorAction SilentlyContinue

Write-Host "[8/9] Creating or reusing HTTP API Gateway..."
$ApiId = (Invoke-Checked -Step "apigatewayv2 get-apis" -Command {
    aws apigatewayv2 get-apis --region $Region --query "Items[?Name=='$ApiName'].ApiId | [0]" --output text
} | Out-String).Trim()
if (-not $ApiId -or $ApiId -eq "None") {
    $ApiId = (Invoke-Checked -Step "apigatewayv2 create-api" -Command {
        aws apigatewayv2 create-api --name $ApiName --protocol-type HTTP --region $Region --query ApiId --output text
    } | Out-String).Trim()
}

$LambdaArn = (Invoke-Checked -Step "lambda get-function arn" -Command {
    aws lambda get-function --function-name $FunctionName --region $Region --query "Configuration.FunctionArn" --output text
} | Out-String).Trim()
$IntegrationUri = "arn:aws:apigateway:${Region}:lambda:path/2015-03-31/functions/${LambdaArn}/invocations"

$IntegrationId = (Invoke-Checked -Step "apigatewayv2 create-integration" -Command {
    aws apigatewayv2 create-integration `
        --api-id $ApiId `
        --integration-type AWS_PROXY `
        --integration-uri $IntegrationUri `
        --payload-format-version "2.0" `
        --region $Region `
        --query IntegrationId --output text
} | Out-String).Trim()

$route1 = aws apigatewayv2 create-route --api-id $ApiId --route-key "ANY /{proxy+}" --target "integrations/$IntegrationId" --region $Region 2>&1
if ($LASTEXITCODE -ne 0) {
    $route1Text = ($route1 | Out-String)
    if ($route1Text -match "ConflictException") {
        Write-Host "Route ANY /{proxy+} may already exist; continuing..."
    } else {
        throw "[apigatewayv2 create-route ANY /{proxy+}] failed.`n$route1Text"
    }
}

$route2 = aws apigatewayv2 create-route --api-id $ApiId --route-key "ANY /" --target "integrations/$IntegrationId" --region $Region 2>&1
if ($LASTEXITCODE -ne 0) {
    $route2Text = ($route2 | Out-String)
    if ($route2Text -match "ConflictException") {
        Write-Host "Route ANY / may already exist; continuing..."
    } else {
        throw "[apigatewayv2 create-route ANY /] failed.`n$route2Text"
    }
}

$StageExists = $true
$stageCheck = aws apigatewayv2 get-stage --api-id $ApiId --stage-name '$default' --region $Region 2>&1
if ($LASTEXITCODE -ne 0) {
    $stageCheckText = ($stageCheck | Out-String)
    if ($stageCheckText -match "NotFoundException") {
        $StageExists = $false
    } else {
        throw "[apigatewayv2 get-stage] failed.`n$stageCheckText"
    }
}
if (-not $StageExists) {
    Invoke-Checked -Step "apigatewayv2 create-stage" -Command {
        aws apigatewayv2 create-stage --api-id $ApiId --stage-name '$default' --auto-deploy --region $Region | Out-Null
    } | Out-Null
}

$StatementId = "apigw-invoke-$ApiId"
$perm = aws lambda add-permission `
    --function-name $FunctionName `
    --statement-id $StatementId `
    --action lambda:InvokeFunction `
    --principal apigateway.amazonaws.com `
    --source-arn "arn:aws:execute-api:${Region}:${AccountId}:${ApiId}/*/*/*" `
    --region $Region 2>&1
if ($LASTEXITCODE -ne 0) {
    $permText = ($perm | Out-String)
    if ($permText -match "ResourceConflictException") {
        Write-Host "Permission may already exist; continuing..."
    } else {
        throw "[lambda add-permission] failed.`n$permText"
    }
}

$ApiEndpoint = (Invoke-Checked -Step "apigatewayv2 get-api" -Command {
    aws apigatewayv2 get-api --api-id $ApiId --region $Region --query ApiEndpoint --output text
} | Out-String).Trim()

Write-Host "[9/9] Done."
Write-Host "API endpoint: $ApiEndpoint"
Write-Host "Health check:  $ApiEndpoint/health"
Write-Host "Predict URL:   $ApiEndpoint/predict"
Write-Host ""
Write-Host "Phase 5 env configured: MongoDB + SMTP + PDF reports dir"
Write-Host "Reports dir on Lambda: $ReportsDir"
Write-Host ""
Write-Host "Example request (PowerShell):"
Write-Host "`$body = @{ url = 'https://github.com' } | ConvertTo-Json"
Write-Host "Invoke-RestMethod -Uri '$ApiEndpoint/predict' -Method Post -Headers @{ 'x-api-key' = '$ApiKeys' } -ContentType 'application/json' -Body `$body"
