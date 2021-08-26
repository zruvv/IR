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
_____      _ _           _       _______ _              __          ___           _                   
/ ____|    | | |         | |     |__   __| |             \ \        / (_)         | |                  
| |     ___ | | | ___  ___| |_ ______| |  | |__   ___ ______ \  /\  / / _ _ __   __| | _____      _____ 
| |    / _ \| | |/ _ \/ __| __|______| |  | '_ \ / _ \______\ \/  \/ / | | '_ \ / _` |/ _ \ \ /\ / / __|
| |____ (_) | | |  __/ (__| |_       | |  | | | |  __/       \  /\  /  | | | | | (_| | (_) \ V  V /\__ \
\_____\___/|_|_|\___|\___|\__|      |_|  |_| |_|\___|        \/  \/   |_|_| |_|\__,_|\___/ \_/\_/ |___/
                                                                                                       
                                                                                                       "

#Collect Scheduled Tasks
Get-ScheduledTask | select TaskName, State, Description, Author, date, TaskPath, Triggers | Export-Csv ScheduledTasks.csv

#Collect running processes
Get-Process | Select-Object Name, ID, ProcessName, Description, Product, Path, Company, ProductVersion, StartTime, MainModule |  Export-Csv RunningProcesses.csv

#Collect installed applications
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table –AutoSize | Export-Csv Applications_Installed.csv

#Collect Services
net start >> net_started-services.log

#Collect list of running processes with their associated services in the command prompt
tasklist /svc >> tasklist_with_services_command.log

#Collect AutoStart applications
Get-CimInstance Win32_StartupCommand | Select-Object Name, command, Location, User | Export-Csv Applications_Autostart.csv

#Review Registry Entries
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run >> reg_local_machine_run.log
reg query HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run >> reg_current_user_run.log

#Collect Local Accounts & Groups
net user >> net_user.log
net localgroup administrators >> local_admins_group.log
Get-LocalUser >> Get-LocalUser.log

#Collect Network Connections
netstat -ano >> netstat_ano.log
#Display executables involved in creating connection
netstat -anb >> netstat_anb.log
#Reduce scope by removing local host connections from view
#Get-NetTCPConnection -LocalAddress 192.168.0.14 | Sort-Object LocalPort

#Collect Firewall Settings
netsh advfirewall show currentprofile >> firewall_profiles.log
#View firewall configurations for inbound and outbound rules
netsh firewall show config >> firewall_rules.log

#Review SMB Sharing/Sessions
Get-SMBShare | Export-Csv SMBShares.csv
net use >> smb_shared_resources.log
net session >> smb_sessions.log

#Collect Event Logs
#Get-WinEvent -ListLog *
Get-WinEvent -LogName Security | export-csv EventLog_Security.csv
Get-WinEvent -LogName System | export-csv EventLog_System.csv
Get-WinEvent -LogName Application | export-csv EventLog_Application.csv
Get-WinEvent -LogName Setup| export-csv EventLog_Setup.csv
Get-WinEvent -LogName Microsoft-Windows-TerminalServices-LocalSessionManager/Operational | export-csv EventLog_TS-LocalSession.csv
Get-WinEvent -LogName Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational | export-csv EventLog_TS-RemoteCongetnectionManager.csv 

# Collect all recently modified files
Get-ChildItem -Path "C:\" -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.CreationTime -gt (Get-Date).AddDays(-5) } | Export-Csv FileChanges_C_Drive_5days.csv

#Dump Security Logs & Convert to CSV
#DumpEventLog.vbs ip.address.of.target newfilename.csv "logname(s)"
#DumpEventLog.vbs ip.address.of.target SecurityLogs.csv "Security"