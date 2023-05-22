<#
.SYNOPSIS
    Uninstalls CrowdStrike Falcon
     MIT License

    Copyright © 2022 CrowdStrike, Inc.

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#>
[CmdletBinding()]
param()
Write-Output 'Uninstalling Falcon Sensor...'

$UninstallerName = 'CsUninstallTool.exe'
$UninstallerPath = Join-Path -Path $PSScriptRoot -ChildPath $UninstallerName

if (-not (Test-Path -Path $UninstallerPath))
{
    throw "${UninstallerName} not found."
}

$UninstallerArguments = @(
    , '/quiet'
)

Write-Output 'Running uninstall command...'

$UninstallerProcess = Start-Process -FilePath $UninstallerPath -ArgumentList $UninstallerArguments -PassThru -Wait

if ($UninstallerProcess.ExitCode -ne 0)
{
    throw "Uninstaller returned exit code $($UninstallerProcess.ExitCode)"
}

$AgentService = Get-Service -Name CSAgent -ErrorAction SilentlyContinue
if ($AgentService -and $AgentService.Status -eq 'Running')
{
    throw 'Service uninstall failed...'
}

if (Test-Path -Path HKLM:\System\Crowdstrike)
{
    throw 'Registry key removal failed...'
}

if (Test-Path -Path"${env:SYSTEMROOT}\System32\drivers\CrowdStrike")
{
    throw 'Driver removal failed...'
}

Write-Output 'Successfully finished uninstall...'
