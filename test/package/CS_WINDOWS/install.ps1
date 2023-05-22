<#
.SYNOPSIS
    Installs CrowdStrike Falcon

    MIT License

    Copyright © 2022 CrowdStrike, Inc.

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#>
[CmdletBinding()]
param()
Write-Output 'Installing Falcon Sensor...'

if (-not $env:SSM_CS_WINDOWS_PRESIGNED_URLS) {
    Write-Output 'Missing required param SSM_CS_WINDOWS_PRESIGNED_URLS. Unable to download the installer without this param.
    
    Verify the Windows Presigned SSM Parameter store parameter exists and is being updated'
    exit 1
}

$WindowsPresignedEnvVar = ConvertFrom-Json $env:SSM_CS_WINDOWS_PRESIGNED_URLS

# Check if the "all" key exists
if ($jsonObject.'all' -eq $null) {
    Write-Output 'Unable to grab the presigned URL, from the SSM_CS_WINDOWS_PRESIGNED_URLS environment variable. Missing "all" key.
    
    Verify the Windows Presigned SSM Parameter store parameter exists and is being updated'
    exit 1
}

PresignedUrl = $WindowsPresignedEnvVar.'all'
# Grab file name from the presigned URL
$Uri = New-Object System.Uri($PresignedUrl)
$InstallerName = [System.IO.Path]::GetFileName($Uri)
$InstallerPath = Join-Path -Path $PSScriptRoot -ChildPath $InstallerName

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 
$resp = Invoke-RestMethod -Method Get -Uri $Uri -OutFile $InstallerPath -ErrorAction Stop

if (-not (Test-Path -Path $InstallerPath)) {
    throw "Failed to download the file. Error $(ConvertTo-Json $resp -Depth 10)"
}

if (-not $env:SSM_CS_CCID) {
    throw "Missing required param $($env:SSM_CS_CCID). Ensure the target instance is running the latest SSM agent version"
}

$InstallArguments = @(
    , '/install'
    , '/quiet'
    , '/norestart'
    , "CID=${env:SSM_CS_CCID}"
    , 'ProvWaitTime=1200'
)

if ($env:SSM_CS_INSTALLTOKEN) {
    $InstallArguments += "ProvToken=${env:SSM_CS_INSTALLTOKEN}"
}

$Space = ' '
if ($env:SSM_CS_INSTALLPARAMS) {
    $InstallArguments += $env:SSM_CS_INSTALLPARAMS.Split($Space)
}

Write-Output 'Running installer...'
$InstallerProcess = Start-Process -FilePath $InstallerPath -ArgumentList $InstallArguments -PassThru -Wait

if ($InstallerProcess.ExitCode -ne 0) {
    throw "Installer returned exit code $($InstallerProcess.ExitCode)"
}

$AgentService = Get-Service -Name CSAgent -ErrorAction SilentlyContinue
if (-not $AgentService) {
    throw 'Installer completed, but CSAgent service is missing...'
}
elseif ($AgentService.Status -eq 'Running') {
    Write-Output 'CSAgent service running...'
}
else {
    throw 'Installer completed, but CSAgent service is not running...'
}

Write-Output 'Successfully completed installation...'
