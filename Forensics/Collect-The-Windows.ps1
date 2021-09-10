<#
    .SYNOPSIS
        Collects local Windows data for Forensic purposes.
    .DESCRIPTION
        -   Collect forensic data from local system and export to local folder as evidence, should be run as administrator for all commands to run properly.
    .NOTES
        File Name: Collect-The-Windows.ps1
        Last Updated: 8/26/2021
        Author: Mike Wurz
#>

Write-Host "
 _____       _ _           _       _______ _              __          __            _                    
/ ____|     | | |         | |     |__   __| |             \ \        / (_)         | |                  
| |     ___ | | | ___  ___| |_ ______| |  | |__   ___ ______ \  /\  / / _ _ __   __| | _____      _____ 
| |    / _ \| | |/ _ \/ __| __|______| |  | '_ \ / _ \______\ \/  \/ / | | '_ \ / _` |/ _ \ \ /\ / / __|
| |____ (_) | | |  __/ (__| |_       | |  | | | |  __/       \  /\  /  | | | | | (_| | (_) \ V  V /\__ \
\ _____\___/|_|_|\___|\___|\__|      |_|  |_| |_|\___|        \/  \/   |_|_| |_|\__,_|\___/ \_/\_/ |___/    "

Write-Host "Run as Administrator to collect data from all areas (example: Security event logs)`n"

#Collect Scheduled Tasks
Write-Host "Collecting Scheduled Tasks"
Get-ScheduledTask | Select-Object TaskName, State, Description, Author, date, TaskPath, Triggers | Export-Csv ScheduledTasks.csv
Write-Host "Schedules Tasks Collected`n" -ForegroundColor Green

#Collect running processes
Write-Host "Collecting Running Processes"
Get-Process | Select-Object Name, ID, ProcessName, Description, Product, Path, Company, ProductVersion, StartTime, MainModule |  Export-Csv RunningProcesses.csv
Write-Host "Processes Collected`n" -ForegroundColor Green

#Collect installed applications
Write-Host "Collecting Installed Applications"
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table –AutoSize | Export-Csv Applications_Installed.csv
Write-Host "Applications Collected`n" -ForegroundColor Green

#Collect Services
Write-Host "Collecting Services"
net start >> net_started-services.log
Write-Host "Services Collected`n" -ForegroundColor Green

#Collect list of running processes with their associated services in the command prompt
Write-Host "Collecting Running Processes with Services & their executed commands"
tasklist /svc >> tasklist_with_services_command.log
Write-Host "Running Processes Collected`n" -ForegroundColor Green

#Collect AutoStart applications
Write-Host "Collecting AutoStart Applications"
Get-CimInstance Win32_StartupCommand | Select-Object Name, command, Location, User | Export-Csv Applications_Autostart.csv
Write-Host "AutoStart Applications Collected`n" -ForegroundColor Green

#Review Registry Entries
Write-Host "Collecting Startup Registry Keys Applications"
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run >> reg_local_machine_run.log
reg query HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run >> reg_current_user_run.log
Write-Host "Startup Registry Keys Collected`n" -ForegroundColor Green

#Collect Local Accounts & Groups
Write-Host "Collecting Local Accounts & Groups Applications"
net user >> net_user.log
net localgroup administrators >> local_admins_group.log
Get-LocalUser >> Get-LocalUser.log
Write-Host "Local Accounts & Groups Collected`n" -ForegroundColor Green


#Collect Network Connections
Write-Host "Collecting Network Connections"
netstat -ano >> netstat_ano.log
#Display executables involved in creating connection
netstat -anb >> netstat_anb.log
#Reduce scope by removing local host connections from view
#Get-NetTCPConnection -LocalAddress 192.168.0.14 | Sort-Object LocalPort
Write-Host "Network Connections Collected`n" -ForegroundColor Green


#Collect Firewall Settings
Write-Host "Collecting Firewall Settings"
netsh advfirewall show currentprofile >> firewall_profiles.log
#View firewall configurations for inbound and outbound rules
netsh firewall show config >> firewall_rules.log
Write-Host "Firewall Settings Collected`n" -ForegroundColor Green

#Review SMB Sharing/Sessions
Write-Host "Collecting SMB Data"
Get-SMBShare | Export-Csv SMBShares.csv
net use >> smb_shared_resources.log
net session >> smb_sessions.log
Write-Host "SMB Data Collected`n" -ForegroundColor Green

Write-Host "Copying Raw .evtx Event Log files"
Copy-Item C:\WINDOWS\System32\winevt\Logs\Security.evtx
Copy-Item C:\WINDOWS\System32\winevt\Logs\System.evtx
Copy-Item C:\WINDOWS\System32\winevt\Logs\Application.evtx
Copy-Item C:\WINDOWS\System32\winevt\Logs\Setup.evtx
Copy-Item C:\WINDOWS\System32\winevt\Logs\Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx
Copy-Item C:\WINDOWS\System32\winevt\Logs\Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Admin.evtx
Write-Host "Completed copying of Event Log files`n" -ForegroundColor Green

# Collect all recently modified files (Can take a while...Need to switch to Write-Progress)
Write-Host "Collecting Recently Modified Files"
Get-ChildItem -Path "C:\" -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.CreationTime -gt (Get-Date).AddDays(-1) } | Export-Csv FileChanges_C_Drive_1day.csv
Write-Host "Recently Modified Files Collected`n" -ForegroundColor Green

#Collect Event Logs (Parsing through the logs takes way too long....Need to switch to Write-Progress)
#Get-WinEvent -ListLog *
<#
Write-Host "Collecting Security Event Logs and parsing to CSV"
Get-WinEvent -LogName Security | export-csv EventLog_Security.csv
Write-Host "Security Event Logs Parsed`n" -ForegroundColor Green
Write-Host "Collecting System Event Logs and parsing to CSV"
Get-WinEvent -LogName System | export-csv EventLog_System.csv
Write-Host "System Event Logs Parsed`n" -ForegroundColor Green
Write-Host "Collecting Application Event Logs and parsing to CSV"
Get-WinEvent -LogName Application | export-csv EventLog_Application.csv
Write-Host "Application Event Logs Parsed`n" -ForegroundColor Green
Write-Host "Collecting Setup Event Logs and parsing to CSV"
Get-WinEvent -LogName Setup| export-csv EventLog_Setup.csv
Write-Host "Setup Event Logs Parsed`n" -ForegroundColor Green
#>

#Dump Security Logs & Convert to CSV (VBS script can be downloaded from SANS and used on legacy systems that do not have PowerShell)
#DumpEventLog.vbs ip.address.of.target newfilename.csv "logname(s)"
#DumpEventLog.vbs ip.address.of.target SecurityLogs.csv "Security"