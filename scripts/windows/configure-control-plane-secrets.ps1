param(
    [string]$Repository = "washingtonmsdj/ordax-control-plane",
    [string]$Environment = "cloudflare-v3"
)

$ErrorActionPreference = "Stop"

function ConvertFrom-SecureStringPlain {
    param([Parameter(Mandatory=$true)][Security.SecureString]$Secure)
    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
    }
}

if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
    throw "GitHub CLI (gh) is required."
}

& gh auth status *> $null
if ($LASTEXITCODE -ne 0) {
    throw "GitHub CLI is not authenticated."
}

$cloudflareSecure = Read-Host "Cloudflare API token (input hidden)" -AsSecureString
$cloudflareToken = ConvertFrom-SecureStringPlain -Secure $cloudflareSecure
if ([string]::IsNullOrWhiteSpace($cloudflareToken)) {
    throw "Cloudflare API token is required."
}

$operatorBytes = New-Object byte[] 48
[Security.Cryptography.RandomNumberGenerator]::Fill($operatorBytes)
$operatorToken = [Convert]::ToBase64String($operatorBytes).TrimEnd('=').Replace('+','-').Replace('/','_')

try {
    $cloudflareToken | & gh secret set CLOUDFLARE_API_TOKEN --repo $Repository --env $Environment
    if ($LASTEXITCODE -ne 0) { throw "Failed to set CLOUDFLARE_API_TOKEN." }

    $operatorToken | & gh secret set ORDAX_OPERATOR_TOKEN --repo $Repository --env $Environment
    if ($LASTEXITCODE -ne 0) { throw "Failed to set ORDAX_OPERATOR_TOKEN." }
}
finally {
    $cloudflareToken = $null
    $operatorToken = $null
    [GC]::Collect()
}

$names = @(
    & gh secret list --repo $Repository --env $Environment --json name |
        ConvertFrom-Json |
        ForEach-Object { $_.name }
)

$required = @("CLOUDFLARE_API_TOKEN", "ORDAX_OPERATOR_TOKEN")
$missing = @($required | Where-Object { $_ -notin $names })
if ($missing.Count -gt 0) {
    throw ("Missing required environment secrets after provisioning: " + ($missing -join ", "))
}

Write-Output "ORDAX_CONTROL_PLANE_SECRETS=READY"
Write-Output "Repository=$Repository"
Write-Output "Environment=$Environment"
