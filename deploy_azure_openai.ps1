<#
.SYNOPSIS
    Provision an Azure OpenAI resource + model deployment for Scenario 1
    (the External Chatbot Abuse Lab), then print the exact configuration the
    lab's `--provider azure` engine expects.

.DESCRIPTION
    The lab's Azure engine (chatbot/engines/azure_openai_engine.py) reads its
    configuration from four environment variables:

        AZURE_OPENAI_ENDPOINT      https://<resource>.openai.azure.com   (required)
        AZURE_OPENAI_API_KEY       the resource key                      (required*)
        AZURE_OPENAI_DEPLOYMENT    the deployment name to call           (required)
        AZURE_OPENAI_API_VERSION   defaults to 2024-10-21                (optional)

        * or AZURE_OPENAI_AD_TOKEN for Entra ID auth instead of a key.

    This script creates a resource group, a Cognitive Services account of kind
    OpenAI, and a model deployment, then reads those four values back and prints
    ready-to-paste commands for PowerShell and bash. Optionally it writes them to
    a .env.azure file (gitignored — it holds a live key).

    It is built on the Azure CLI (`az`), which is the most reliable path for
    Azure OpenAI provisioning and runs under pwsh on Linux, macOS and Windows.

.PREREQUISITES
    - Azure CLI installed and on PATH:  https://aka.ms/azure-cli
    - Signed in:                        az login
    - A subscription with access to Azure OpenAI. Some tenants still gate it;
      if account creation fails with a policy/quota error, request access for
      the subscription first.

.EXAMPLE
    # Simplest run — sensible defaults, prompts for nothing:
    pwsh ./deploy_azure_openai.ps1

.EXAMPLE
    # Pin everything explicitly and write the env file:
    pwsh ./deploy_azure_openai.ps1 -ResourceGroup rg-nora-lab -Location eastus2 `
        -AccountName nora-lab-aoai-01 -DeploymentName nora-gpt4o `
        -ModelName gpt-4o -ModelVersion 2024-11-20 -WriteEnvFile

.EXAMPLE
    # The account already exists and you just want to see what models/versions
    # you can deploy in its region before choosing:
    pwsh ./deploy_azure_openai.ps1 -AccountName nora-lab-aoai-01 `
        -ResourceGroup rg-nora-lab -ListModels

.NOTES
    Tear everything down when the demo is over:
        az group delete --name <ResourceGroup> --yes --no-wait
#>

[CmdletBinding()]
param(
    # Azure subscription to deploy into. Defaults to your current `az` context.
    [string]$SubscriptionId,

    # Resource group. Created if it does not exist.
    [string]$ResourceGroup = "rg-nora-openai-lab",

    # Azure region. Must offer the chosen model + deployment SKU. eastus/eastus2
    # are the safest bets for gpt-4o on GlobalStandard.
    [string]$Location = "eastus",

    # Cognitive Services account name. Must be globally unique and becomes the
    # subdomain of your endpoint (https://<AccountName>.openai.azure.com). A
    # random suffix is appended when you don't supply one.
    [string]$AccountName,

    # The deployment name the lab calls. This is AZURE_OPENAI_DEPLOYMENT — on
    # Azure the model is addressed by deployment name, not model id.
    [string]$DeploymentName = "nora-chat",

    # Model to deploy. gpt-4o is a good, broadly-available default for the demo.
    # A reasoning model (e.g. o4-mini) will also exercise the engine's
    # reasoning_effort mapping; the engine retries without it on models that
    # reject it, so either works.
    [string]$ModelName = "gpt-4o",

    # Model version. Leave as the default or run with -ListModels first to see
    # what's actually deployable in your region.
    [string]$ModelVersion = "2024-11-20",

    # Deployment SKU (capacity type). GlobalStandard has the widest availability
    # and highest quota; Standard is region-pinned.
    [ValidateSet("GlobalStandard", "Standard", "DataZoneStandard")]
    [string]$SkuName = "GlobalStandard",

    # Deployment capacity, in thousands of tokens/min. 10 is plenty for a demo.
    [int]$Capacity = 10,

    # API version reported back for AZURE_OPENAI_API_VERSION. The lab defaults to
    # this same value if the variable is unset.
    [string]$ApiVersion = "2024-10-21",

    # List deployable models for the account's region, then exit. Requires the
    # account to already exist (or to be created this run).
    [switch]$ListModels,

    # Also write the config to ./.env.azure (gitignored). It contains a live key.
    [switch]$WriteEnvFile
)

# Stop on any error and make native (az) failures throw where the CLI supports it.
$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function Invoke-Az {
    <#  Run `az` and fail loudly on a non-zero exit. Returns stdout as a string.
        We check $LASTEXITCODE because az writes errors to stderr and does not
        throw on its own. #>
    param([Parameter(Mandatory)][string[]]$Args)
    $out = & az @Args 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "az $($Args -join ' ') failed:`n$out"
    }
    return ($out | Out-String)
}

function Write-Step { param([string]$Msg) Write-Host "[deploy] $Msg" -ForegroundColor Cyan }
function Write-Ok   { param([string]$Msg) Write-Host "[ ok  ] $Msg" -ForegroundColor Green }

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------

if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    throw "Azure CLI (az) not found on PATH. Install it: https://aka.ms/azure-cli"
}

# Confirm we're logged in. `az account show` exits non-zero when there's no
# active session.
& az account show 1>$null 2>$null
if ($LASTEXITCODE -ne 0) {
    throw "Not signed in to Azure. Run:  az login"
}

if ($SubscriptionId) {
    Write-Step "Selecting subscription $SubscriptionId"
    Invoke-Az @("account", "set", "--subscription", $SubscriptionId) | Out-Null
}

$sub = Invoke-Az @("account", "show", "-o", "json") | ConvertFrom-Json
Write-Ok "Subscription: $($sub.name) ($($sub.id))"

# Generate a unique account name if none was given.
if (-not $AccountName) {
    $suffix = -join ((48..57) + (97..122) | Get-Random -Count 6 | ForEach-Object { [char]$_ })
    $AccountName = "nora-aoai-$suffix"
    Write-Step "No -AccountName given; using generated name '$AccountName'"
}

# ---------------------------------------------------------------------------
# Resource provider + resource group
# ---------------------------------------------------------------------------

Write-Step "Ensuring the Microsoft.CognitiveServices provider is registered"
Invoke-Az @("provider", "register", "--namespace", "Microsoft.CognitiveServices") | Out-Null

$rgExists = (& az group exists --name $ResourceGroup) -eq "true"
if (-not $rgExists) {
    Write-Step "Creating resource group '$ResourceGroup' in $Location"
    Invoke-Az @("group", "create", "--name", $ResourceGroup, "--location", $Location) | Out-Null
    Write-Ok "Resource group created"
} else {
    Write-Ok "Resource group '$ResourceGroup' already exists"
}

# ---------------------------------------------------------------------------
# Cognitive Services account (kind OpenAI)
# ---------------------------------------------------------------------------

# --custom-domain gives the account the subdomain Azure OpenAI needs for its
# https://<name>.openai.azure.com endpoint (and for Entra token auth).
$acctShow = & az cognitiveservices account show `
    --name $AccountName --resource-group $ResourceGroup -o json 2>$null
if ($LASTEXITCODE -eq 0 -and $acctShow) {
    Write-Ok "OpenAI account '$AccountName' already exists — reusing it"
} else {
    Write-Step "Creating Azure OpenAI account '$AccountName' (this can take a minute)"
    Invoke-Az @(
        "cognitiveservices", "account", "create",
        "--name", $AccountName,
        "--resource-group", $ResourceGroup,
        "--location", $Location,
        "--kind", "OpenAI",
        "--sku", "S0",
        "--custom-domain", $AccountName,
        "--yes"
    ) | Out-Null
    Write-Ok "Account created"
}

# ---------------------------------------------------------------------------
# Optional: list deployable models and exit
# ---------------------------------------------------------------------------

if ($ListModels) {
    Write-Step "Models deployable to '$AccountName' in ${Location}:"
    $models = Invoke-Az @(
        "cognitiveservices", "account", "list-models",
        "--name", $AccountName, "--resource-group", $ResourceGroup, "-o", "json"
    ) | ConvertFrom-Json
    $models |
        Where-Object { $_.model.format -eq "OpenAI" } |
        Select-Object `
            @{n = "model"; e = { $_.model.name } },
            @{n = "version"; e = { $_.model.version } },
            @{n = "skus"; e = { ($_.model.skus.name) -join ", " } } |
        Sort-Object model, version |
        Format-Table -AutoSize
    Write-Host "Re-run without -ListModels, passing -ModelName / -ModelVersion / -SkuName from above." -ForegroundColor Yellow
    return
}

# ---------------------------------------------------------------------------
# Model deployment
# ---------------------------------------------------------------------------

$depShow = & az cognitiveservices account deployment show `
    --name $AccountName --resource-group $ResourceGroup `
    --deployment-name $DeploymentName -o json 2>$null
if ($LASTEXITCODE -eq 0 -and $depShow) {
    Write-Ok "Deployment '$DeploymentName' already exists — reusing it"
} else {
    Write-Step "Deploying model $ModelName ($ModelVersion) as '$DeploymentName' [$SkuName x$Capacity]"
    try {
        Invoke-Az @(
            "cognitiveservices", "account", "deployment", "create",
            "--name", $AccountName,
            "--resource-group", $ResourceGroup,
            "--deployment-name", $DeploymentName,
            "--model-name", $ModelName,
            "--model-version", $ModelVersion,
            "--model-format", "OpenAI",
            "--sku-name", $SkuName,
            "--sku-capacity", "$Capacity"
        ) | Out-Null
        Write-Ok "Deployment created"
    } catch {
        Write-Host $_.Exception.Message -ForegroundColor Red
        Write-Host ""
        Write-Host "The model/version/SKU combination was likely not available in $Location." -ForegroundColor Yellow
        Write-Host "See what IS deployable here, then re-run with those values:" -ForegroundColor Yellow
        Write-Host "  pwsh ./deploy_azure_openai.ps1 -AccountName $AccountName -ResourceGroup $ResourceGroup -ListModels" -ForegroundColor Yellow
        throw
    }
}

# ---------------------------------------------------------------------------
# Read back the values the lab needs
# ---------------------------------------------------------------------------

Write-Step "Reading endpoint and key"
$endpoint = (Invoke-Az @(
        "cognitiveservices", "account", "show",
        "--name", $AccountName, "--resource-group", $ResourceGroup,
        "--query", "properties.endpoint", "-o", "tsv"
    )).Trim()

$key = (Invoke-Az @(
        "cognitiveservices", "account", "keys", "list",
        "--name", $AccountName, "--resource-group", $ResourceGroup,
        "--query", "key1", "-o", "tsv"
    )).Trim()

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

$maskedKey = if ($key.Length -gt 8) { $key.Substring(0, 4) + "..." + $key.Substring($key.Length - 4) } else { "****" }

Write-Host ""
Write-Host "==================== Azure OpenAI is ready ====================" -ForegroundColor Green
Write-Host ""
Write-Host "  Endpoint    : $endpoint"
Write-Host "  Deployment  : $DeploymentName"
Write-Host "  Model       : $ModelName ($ModelVersion)"
Write-Host "  API version : $ApiVersion"
Write-Host "  Key         : $maskedKey  (full value in the commands below)"
Write-Host ""
Write-Host "--- PowerShell (this session) --------------------------------" -ForegroundColor Cyan
Write-Host "`$env:AZURE_OPENAI_ENDPOINT    = `"$endpoint`""
Write-Host "`$env:AZURE_OPENAI_API_KEY     = `"$key`""
Write-Host "`$env:AZURE_OPENAI_DEPLOYMENT  = `"$DeploymentName`""
Write-Host "`$env:AZURE_OPENAI_API_VERSION = `"$ApiVersion`""
Write-Host ""
Write-Host "--- bash / zsh -----------------------------------------------" -ForegroundColor Cyan
Write-Host "export AZURE_OPENAI_ENDPOINT=$endpoint"
Write-Host "export AZURE_OPENAI_API_KEY=$key"
Write-Host "export AZURE_OPENAI_DEPLOYMENT=$DeploymentName"
Write-Host "export AZURE_OPENAI_API_VERSION=$ApiVersion"
Write-Host ""
Write-Host "--- then run the lab -----------------------------------------" -ForegroundColor Cyan
Write-Host "pip install openai"
Write-Host "python3 lab.py --provider azure"
Write-Host "# know which vectors land before a live demo:"
Write-Host "python3 attacks/preflight.py --runs 5"
Write-Host ""

if ($WriteEnvFile) {
    $envPath = Join-Path (Get-Location) ".env.azure"
    @(
        "# Azure OpenAI config for Scenario 1 — generated $(Get-Date -Format o)"
        "# Contains a LIVE KEY. Do not commit (it is gitignored)."
        "# Load into bash with:  set -a; source .env.azure; set +a"
        "AZURE_OPENAI_ENDPOINT=$endpoint"
        "AZURE_OPENAI_API_KEY=$key"
        "AZURE_OPENAI_DEPLOYMENT=$DeploymentName"
        "AZURE_OPENAI_API_VERSION=$ApiVersion"
    ) | Set-Content -Path $envPath -Encoding utf8
    Write-Ok "Wrote $envPath (gitignored — holds a live key)"
    Write-Host ""
}

Write-Host "Tear it all down when finished:" -ForegroundColor Yellow
Write-Host "  az group delete --name $ResourceGroup --yes --no-wait"
