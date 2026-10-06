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

$cloudflareSecure = Read-Host "Cloudflare Worker deploy API token (input hidden)" -AsSecureString
$cloudflareToken = ConvertFrom-SecureStringPlain -Secure $cloudflareSecure
if ([string]::IsNullOrWhiteSpace($cloudflareToken)) {
    throw "Cloudflare API token is required."
}

try {
    $cloudflareToken | & gh secret set CLOUDFLARE_API_TOKEN --repo $Repository --env $Environment
    if ($LASTEXITCODE -ne 0) { throw "Failed to set CLOUDFLARE_API_TOKEN." }
}
finally {
    $cloudflareToken = $null
    [GC]::Collect()
}

$names = @(
    & gh secret list --repo $Repository --env $Environment --json name |
        ConvertFrom-Json |
        ForEach-Object { $_.name }
)

if ("CLOUDFLARE_API_TOKEN" -notin $names) {
    throw "Missing CLOUDFLARE_API_TOKEN after provisioning."
}

Write-Output "ORDAX_CONTROL_PLANE_DEPLOY_SECRET=READY"
Write-Output "Repository=$Repository"
Write-Output "Environment=$Environment"
