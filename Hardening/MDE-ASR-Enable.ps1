﻿<# 

    .SYNOPSIS
        Enable Microsoft Defender for Endpoint's Attack Surface Reduction (ASR) rules.
    .DESCRIPTION
        Enables MDE ASR rules in Auditing or Blocking Mode based on user's selection
    .NOTES
        File Name: MDE-ASR-Enable.ps1
        Last Updated: 9/17/2021
        Author: Mike Wurz
   
#>


# =================================================================================================
#                                              Functions
# =================================================================================================

# Verifies that the script is running as admin
function Check-IsElevated
{
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object System.Security.Principal.WindowsPrincipal($id)

    if ($p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator))
    {
        Write-Output $true
    }            
    else
    {
        Write-Output $false
    }       
}

# Verifies that script is running on Windows 10 or greater
function Check-IsWindows10
{
    if ([System.Environment]::OSVersion.Version.Major -ge "10" -and [System.Environment]::OSVersion.Version.Build -ge "16299")  
    {
        Write-Output $true
    }
    else
    {
        Write-Output $false
    }
}

# =================================================================================================
#                                              Main
# =================================================================================================

if (!(Check-IsElevated))
{
    throw "Please run this script from an elevated PowerShell prompt"            
}

if (!(Check-IsWindows10))
{
    throw "Please run this script on Windows 10"            
}

#Custom IF statement to verify device is onboarded to MDATP, exits with error code 1 indicating script failed to set ASR rules - mwurz
Write-Host "`nUpdating Windows Defender AV settings`n" -ForegroundColor Green 


Write-Host "Enabling Exploit Guard ASR rules and setting to audit mode"
Add-MpPreference -AttackSurfaceReductionRules_Ids 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids 3B576869-A4EC-4529-8536-B80A7769E899 -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EfC-AADC-AD5F3C50688A -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids D3E037E1-3EB8-44C8-A917-57927947596D -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids 92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids D1E49AAC-8F56-4280-B9BA-993A6D77406C -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4 -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids C1DB55AB-C21A-4637-BB3F-A12568109D35 -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids 01443614-CD74-433A-B99E-2ECDC07BFC25 -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids 26190899-1602-49e8-8b27-eb1d0a1ce869 -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids 7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids e6db77e5-3df2-4cf1-b95a-636979351e5b -AttackSurfaceReductionRules_Actions Enabled

Write-Host "`nSettings update complete"  -ForegroundColor Green

Write-Host "`nOutput Windows Defender AV settings status"  -ForegroundColor Green
Get-MpPreference

exit 0