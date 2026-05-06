"""
SOCPilots — Knowledge Ingestion Service
Ingests MITRE ATT&CK techniques, TheHive historical incidents, Wazuh
detection rules, post-incident reports, and SOC response procedures
into Qdrant ("socpilots_knowledge") with 384-dim bge-small-en-v1.5 embeddings.
Neo4j is no longer used by this service.
"""

import os
import json
import logging
import requests
from datetime import datetime, timezone
from qdrant_client import QdrantClient
from qdrant_client.models import (
    Distance,
    VectorParams,
    PointStruct,
    Filter,
    FieldCondition,
    MatchValue,
    CountRequest,
)
from sentence_transformers import SentenceTransformer

log = logging.getLogger(__name__)

# ── MITRE ATT&CK knowledge base (55 key techniques) ─────────────

MITRE_TECHNIQUES = [
    # ── Initial Access ──────────────────────────────────────────
    {"id": "T1566", "tactic": "Initial Access", "name": "Phishing",
     "description": "Adversaries send malicious emails with links or attachments to gain initial access. Variants include spearphishing attachment (T1566.001), spearphishing link (T1566.002), and spearphishing via service (T1566.003). IOCs: suspicious email attachments, macro-enabled Office docs, encoded PowerShell in email links."},
    {"id": "T1190", "tactic": "Initial Access", "name": "Exploit Public-Facing Application",
     "description": "Adversaries exploit vulnerabilities in internet-facing applications such as web servers, VPNs, firewalls, or other exposed services. Common targets: Apache Log4Shell, F5 BIG-IP, Citrix ADC, Exchange ProxyLogon. IOCs: SQL injection patterns, web shell uploads, unusual HTTP 500 errors."},
    {"id": "T1078", "tactic": "Initial Access, Persistence, Defense Evasion, Privilege Escalation", "name": "Valid Accounts",
     "description": "Adversaries obtain and abuse credentials of existing accounts including local, domain, cloud, and service accounts. Used for initial access via VPN/RDP/SSH with stolen credentials. IOCs: logins from unusual IPs, impossible travel, off-hours access, multiple failed logins then success."},
    {"id": "T1133", "tactic": "Initial Access, Persistence", "name": "External Remote Services",
     "description": "Adversaries abuse VPN, RDP, Citrix, SSH, and other remote access services for initial access or persistence. Often combined with valid accounts. IOCs: brute force against RDP (port 3389), VPN logins from unusual countries, repeated authentication failures."},
    {"id": "T1189", "tactic": "Initial Access", "name": "Drive-by Compromise",
     "description": "Adversaries gain access through malicious code embedded in websites visited by targets. Often uses exploit kits targeting browser vulnerabilities. IOCs: unusual browser process spawning child processes, download of executables from new domains."},

    # ── Execution ────────────────────────────────────────────────
    {"id": "T1059", "tactic": "Execution", "name": "Command and Scripting Interpreter",
     "description": "Adversaries abuse command-line interfaces and scripting engines: PowerShell (T1059.001), cmd.exe (T1059.003), Bash (T1059.004), Python (T1059.006), VBScript (T1059.005). IOCs: encoded PowerShell (-EncodedCommand, -Enc), cmd spawning unusual children, wscript/cscript executing scripts."},
    {"id": "T1204", "tactic": "Execution", "name": "User Execution",
     "description": "Adversaries rely on users to execute malicious files or links. Malicious file (T1204.002) involves Office macros, LNK shortcuts, disguised executables. IOCs: Office process spawning cmd/PowerShell, user executing file from Downloads/Temp, macro-enabled documents."},
    {"id": "T1053", "tactic": "Execution, Persistence, Privilege Escalation", "name": "Scheduled Task/Job",
     "description": "Adversaries abuse Windows Task Scheduler, cron, or at command to execute programs at startup or on schedule. IOCs: schtasks.exe creating new tasks, at.exe usage, cron job modifications, tasks pointing to temp directories."},
    {"id": "T1569", "tactic": "Execution", "name": "System Services",
     "description": "Adversaries abuse system services to execute commands. Service execution (T1569.002) uses Windows Service Control Manager. IOCs: sc.exe creating services, services with random names, services pointing to suspicious paths."},

    # ── Persistence ──────────────────────────────────────────────
    {"id": "T1547", "tactic": "Persistence, Privilege Escalation", "name": "Boot or Logon Autostart Execution",
     "description": "Adversaries achieve persistence by adding programs to autostart locations: Run keys (T1547.001), Startup folder (T1547.001), Logon scripts (T1547.003), Winlogon Helper (T1547.004). IOCs: registry modifications to HKCU/HKLM Run keys, files added to Startup folder."},
    {"id": "T1136", "tactic": "Persistence", "name": "Create Account",
     "description": "Adversaries create accounts for persistent access. Local Account (T1136.001) adds Windows local users. Domain Account (T1136.002) adds AD accounts. IOCs: net user /add, New-LocalUser, useradd, AddUser events, unexpected admin account creation."},
    {"id": "T1543", "tactic": "Persistence, Privilege Escalation", "name": "Create or Modify System Process",
     "description": "Adversaries create or modify system-level processes such as Windows Services (T1543.003) or launch agents/daemons (T1543.001, T1543.004). IOCs: sc.exe creating services, LaunchDaemon plist modifications, systemd service file creation."},
    {"id": "T1505", "tactic": "Persistence", "name": "Server Software Component",
     "description": "Adversaries install malicious server components including web shells (T1505.003) on internet-facing servers. IOCs: new PHP/ASP/JSP files in web directories, web requests to unusual file paths, cmd.exe spawned by web server process."},

    # ── Privilege Escalation ─────────────────────────────────────
    {"id": "T1548", "tactic": "Privilege Escalation, Defense Evasion", "name": "Abuse Elevation Control Mechanism",
     "description": "Adversaries bypass UAC (T1548.002) or abuse sudo (T1548.003) to elevate privileges. IOCs: UAC bypass techniques (fodhelper, eventvwr, sdclt), sudo -l enumeration, SUID binary abuse on Linux."},
    {"id": "T1134", "tactic": "Privilege Escalation, Defense Evasion", "name": "Access Token Manipulation",
     "description": "Adversaries manipulate Windows access tokens to escalate privileges or evade detection. Token impersonation (T1134.001), Create Process with Token (T1134.002). IOCs: SeImpersonatePrivilege, SeAssignPrimaryTokenPrivilege, Potato exploits (JuicyPotato, RoguePotato)."},
    {"id": "T1068", "tactic": "Privilege Escalation", "name": "Exploitation for Privilege Escalation",
     "description": "Adversaries exploit kernel or service vulnerabilities to elevate privileges. Common exploits: PrintNightmare (CVE-2021-34527), Dirty Cow, EternalBlue. IOCs: exploit tool artifacts, kernel crash logs, unexpected privilege changes."},

    # ── Defense Evasion ──────────────────────────────────────────
    {"id": "T1562", "tactic": "Defense Evasion", "name": "Impair Defenses",
     "description": "Adversaries disable or tamper with security tools: Disable or Modify Tools (T1562.001), Disable Logging (T1562.002), Indicator Blocking (T1562.006). IOCs: sc stop/delete of AV services, Clear-EventLog, reg delete Security audit keys, tamper protection disabled."},
    {"id": "T1070", "tactic": "Defense Evasion", "name": "Indicator Removal",
     "description": "Adversaries delete artifacts to hide activity: Clear Windows Event Logs (T1070.001), Clear Linux/Mac Logs (T1070.002), File Deletion (T1070.004), Timestomping (T1070.006). IOCs: wevtutil cl, Clear-EventLog, rm -rf /var/log, touch with past timestamps."},
    {"id": "T1027", "tactic": "Defense Evasion", "name": "Obfuscated Files or Information",
     "description": "Adversaries obfuscate payloads to evade detection: Binary Padding (T1027.001), Steganography (T1027.003), Compile After Delivery (T1027.004), encoded PowerShell (T1027.010). IOCs: base64/gzip encoded commands, certutil -decode, chr() in VBScript."},
    {"id": "T1055", "tactic": "Defense Evasion, Privilege Escalation", "name": "Process Injection",
     "description": "Adversaries inject code into legitimate processes to evade defenses: DLL Injection (T1055.001), Process Hollowing (T1055.012), Thread Execution Hijacking (T1055.003). IOCs: CreateRemoteThread, VirtualAllocEx, WriteProcessMemory, unexpected DLLs loaded."},
    {"id": "T1036", "tactic": "Defense Evasion", "name": "Masquerading",
     "description": "Adversaries disguise malicious artifacts as legitimate: rename malware as svchost.exe, use double extensions (invoice.pdf.exe), match legitimate filenames. IOCs: processes in wrong locations (svchost not in system32), mismatched parent-child process relationships."},

    # ── Credential Access ────────────────────────────────────────
    {"id": "T1003", "tactic": "Credential Access", "name": "OS Credential Dumping",
     "description": "Adversaries dump credentials from operating systems: LSASS Memory (T1003.001 - mimikatz), SAM (T1003.002), NTDS (T1003.003 - domain hashes), /etc/shadow (T1003.008). IOCs: lsass.exe memory access, procdump targeting lsass, vssadmin creating shadow copies."},
    {"id": "T1110", "tactic": "Credential Access", "name": "Brute Force",
     "description": "Adversaries guess credentials: Password Guessing (T1110.001), Password Spraying (T1110.003 - low-and-slow), Credential Stuffing (T1110.004). IOCs: multiple failed logins, authentication failures across many accounts, login attempts from single IP."},
    {"id": "T1539", "tactic": "Credential Access", "name": "Steal Web Session Cookie",
     "description": "Adversaries steal session cookies to bypass MFA and authentication. IOCs: cookie theft via XSS, suspicious browser extension activity, session cookies used from different IP/UA."},
    {"id": "T1552", "tactic": "Credential Access", "name": "Unsecured Credentials",
     "description": "Adversaries search for credentials in accessible locations: credentials in files (T1552.001), credentials in registry (T1552.002), bash history (T1552.003), cloud metadata (T1552.005). IOCs: searching for .env, config.php, web.config, finding API keys in repos."},

    # ── Discovery ────────────────────────────────────────────────
    {"id": "T1082", "tactic": "Discovery", "name": "System Information Discovery",
     "description": "Adversaries gather information about system configuration: OS version, architecture, hostname, patches. IOCs: systeminfo, uname -a, Get-ComputerInfo, /proc/version reads, WMI queries for system info."},
    {"id": "T1046", "tactic": "Discovery", "name": "Network Service Discovery",
     "description": "Adversaries scan networks to discover running services. IOCs: nmap, masscan, port scanning patterns, SYN scans, service banner grabbing, unusual ICMP traffic."},
    {"id": "T1087", "tactic": "Discovery", "name": "Account Discovery",
     "description": "Adversaries enumerate user accounts: Local Account (T1087.001), Domain Account (T1087.002). IOCs: net user, net group /domain, Get-ADUser, id command, /etc/passwd reads, ldap queries for accounts."},
    {"id": "T1069", "tactic": "Discovery", "name": "Permission Groups Discovery",
     "description": "Adversaries discover group permissions: Local Groups (T1069.001), Domain Groups (T1069.002). IOCs: net localgroup administrators, Get-LocalGroupMember, id -G, ldap searches for group membership."},
    {"id": "T1057", "tactic": "Discovery", "name": "Process Discovery",
     "description": "Adversaries enumerate running processes to find targets. IOCs: tasklist, Get-Process, ps aux, /proc enumeration, WMI queries for processes."},
    {"id": "T1083", "tactic": "Discovery", "name": "File and Directory Discovery",
     "description": "Adversaries enumerate file system contents. IOCs: dir, ls, find commands, Get-ChildItem, unusual file enumeration in sensitive directories (/etc, C:\\Users)."},

    # ── Lateral Movement ─────────────────────────────────────────
    {"id": "T1021", "tactic": "Lateral Movement", "name": "Remote Services",
     "description": "Adversaries use remote services: SSH (T1021.004), RDP (T1021.001), SMB/Windows Admin Shares (T1021.002), WinRM (T1021.006). IOCs: RDP connections between workstations, lateral SMB connections, PsExec/WMI usage for remote execution."},
    {"id": "T1550", "tactic": "Lateral Movement, Defense Evasion", "name": "Use Alternate Authentication Material",
     "description": "Adversaries use hashed credentials or Kerberos tickets: Pass the Hash (T1550.002), Pass the Ticket (T1550.003). IOCs: NTLM authentication without preceding Kerberos, unusual Kerberos TGT requests, mimikatz pass-the-hash artifacts."},
    {"id": "T1534", "tactic": "Lateral Movement", "name": "Internal Spearphishing",
     "description": "Adversaries use internal access to spearphish targets within the organization. IOCs: internal emails with malicious attachments, shared drives with malicious files, internal messaging with phishing links."},
    {"id": "T1210", "tactic": "Lateral Movement", "name": "Exploitation of Remote Services",
     "description": "Adversaries exploit vulnerabilities in remote services: EternalBlue (SMB), BlueGate (RDP). IOCs: exploit traffic patterns, service crashes, unexpected process spawning from network service, lateral movement from compromised host."},

    # ── Collection ───────────────────────────────────────────────
    {"id": "T1005", "tactic": "Collection", "name": "Data from Local System",
     "description": "Adversaries collect data from local file system for exfiltration. IOCs: mass file reads, staging area creation in temp directories, archive creation (zip, 7z, tar) of sensitive files."},
    {"id": "T1074", "tactic": "Collection", "name": "Data Staged",
     "description": "Adversaries stage collected data prior to exfiltration: Local Data Staging (T1074.001), Remote Data Staging (T1074.002). IOCs: large file creation in temp/unusual locations, archive files, compression utilities."},
    {"id": "T1056", "tactic": "Collection, Credential Access", "name": "Input Capture",
     "description": "Adversaries capture user input: Keylogging (T1056.001), Web Portal Capture (T1056.003). IOCs: SetWindowsHookEx API calls, suspicious process hooking keyboard, credential harvesting web portals."},

    # ── Command and Control ──────────────────────────────────────
    {"id": "T1071", "tactic": "Command and Control", "name": "Application Layer Protocol",
     "description": "Adversaries use application layer protocols for C2: Web Protocols (T1071.001 - HTTP/HTTPS), File Transfer Protocols (T1071.002 - FTP/SFTP), Mail Protocols (T1071.003 - SMTP/IMAP), DNS (T1071.004). IOCs: beaconing patterns, unusual DNS queries, encrypted HTTP to new IPs."},
    {"id": "T1095", "tactic": "Command and Control", "name": "Non-Application Layer Protocol",
     "description": "Adversaries use raw network protocols: ICMP tunneling, custom TCP/UDP. IOCs: unusual ICMP payload sizes, raw socket usage, traffic on non-standard ports."},
    {"id": "T1572", "tactic": "Command and Control", "name": "Protocol Tunneling",
     "description": "Adversaries tunnel C2 traffic inside other protocols to evade detection: DNS tunneling (iodine, dnscat2), HTTP/S tunneling. IOCs: high-volume DNS queries with long subdomains, DNS TXT records with encoded data."},
    {"id": "T1105", "tactic": "Command and Control", "name": "Ingress Tool Transfer",
     "description": "Adversaries transfer tools from external systems: certutil -urlcache, PowerShell DownloadFile, wget/curl, bitsadmin. IOCs: tools downloaded to temp directories, BITSAdmin transfers, certutil decoding base64 files."},
    {"id": "T1219", "tactic": "Command and Control", "name": "Remote Access Software",
     "description": "Adversaries use commercial remote access tools: TeamViewer, AnyDesk, ConnectWise, Cobalt Strike, Metasploit. IOCs: unexpected remote access tool installation, outbound connections to remote access provider IPs, suspicious scheduled tasks."},

    # ── Exfiltration ─────────────────────────────────────────────
    {"id": "T1041", "tactic": "Exfiltration", "name": "Exfiltration Over C2 Channel",
     "description": "Adversaries exfiltrate data over existing C2 channel. IOCs: high volume outbound data over C2 connection, large POST requests, staged data being sent."},
    {"id": "T1048", "tactic": "Exfiltration", "name": "Exfiltration Over Alternative Protocol",
     "description": "Adversaries use alternative protocols for exfiltration: DNS (T1048.003), SMTP, FTP. IOCs: high-volume DNS queries, FTP to external IPs, SMTP from non-mail servers."},
    {"id": "T1567", "tactic": "Exfiltration", "name": "Exfiltration Over Web Service",
     "description": "Adversaries exfiltrate to cloud storage or code repositories: GitHub, Dropbox, OneDrive (T1567.002). IOCs: large uploads to cloud services, unusual API calls to storage providers."},

    # ── Impact ───────────────────────────────────────────────────
    {"id": "T1486", "tactic": "Impact", "name": "Data Encrypted for Impact",
     "description": "Adversaries encrypt victim files and demand ransom: ransomware attacks (Ryuk, REvil, BlackCat, LockBit). IOCs: mass file renaming, encrypted file extensions (.locked, .encrypted, .ryuk), ransom note creation, vssadmin shadow copy deletion, volume shadow copy deletion."},
    {"id": "T1490", "tactic": "Impact", "name": "Inhibit System Recovery",
     "description": "Adversaries prevent recovery by deleting backups: vssadmin delete shadows, wmic shadowcopy delete, bcdedit /set recoveryenabled No. IOCs: volume shadow copy deletion commands, backup service termination, recovery partition removal."},
    {"id": "T1489", "tactic": "Impact", "name": "Service Stop",
     "description": "Adversaries stop services to impair defenses or encrypt locked files. IOCs: net stop, sc stop, taskkill on security services, backup agents, database services stopped before ransomware."},
    {"id": "T1485", "tactic": "Impact", "name": "Data Destruction",
     "description": "Adversaries destroy data to make it unrecoverable: wiper malware (NotPetya, Shamoon), rm -rf, format commands. IOCs: mass file deletion, disk wiping tools, MBR overwrite."},
    {"id": "T1499", "tactic": "Impact", "name": "Endpoint Denial of Service",
     "description": "Adversaries degrade availability of targeted systems: OS Exhaustion Flood, Service Exhaustion Flood. IOCs: high CPU/memory usage, connection exhaustion, crash loops."},
    {"id": "T1529", "tactic": "Impact", "name": "System Shutdown/Reboot",
     "description": "Adversaries shut down or reboot systems to disrupt operations. IOCs: shutdown /s /f, shutdown -h, init 0, unexpected reboots especially after ransomware deployment."},

    # ── Additional high-value detections ────────────────────────
    {"id": "T1112", "tactic": "Defense Evasion", "name": "Modify Registry",
     "description": "Adversaries modify Windows Registry to hide configuration, establish persistence, or disable defenses. IOCs: reg add/delete/export, registry writes to run keys, disabling security features via registry."},
    {"id": "T1218", "tactic": "Defense Evasion", "name": "System Binary Proxy Execution",
     "description": "Adversaries proxy execution through legitimate Windows binaries (LOLBins): mshta.exe, regsvr32.exe, rundll32.exe, certutil.exe, wscript.exe. IOCs: living-off-the-land binaries executing unusual payloads."},
]

# ── Detection rule patterns for SOC operations ──────────────────

SOC_DETECTION_RULES = [
    {"id": "DR001", "name": "SSH Brute Force Detection",
     "description": "Multiple failed SSH login attempts from same source IP within short time window. Threshold: 5+ failures in 60 seconds. Related MITRE: T1110 (Brute Force), T1021 (Remote Services)."},
    {"id": "DR002", "name": "PowerShell Encoded Command Execution",
     "description": "Detection of PowerShell executing encoded commands (-EncodedCommand, -Enc, -e flags) which is commonly used to obfuscate malicious payloads. Related MITRE: T1059.001, T1027."},
    {"id": "DR003", "name": "LSASS Memory Access",
     "description": "Process attempting to read LSASS memory, common indicator of credential dumping tools like Mimikatz. Related MITRE: T1003.001."},
    {"id": "DR004", "name": "Volume Shadow Copy Deletion",
     "description": "Execution of vssadmin delete shadows or wmic shadowcopy delete commands, strong indicator of ransomware preparing for encryption. Related MITRE: T1490, T1486."},
    {"id": "DR005", "name": "Lateral Movement via PsExec",
     "description": "Detection of PsExec or similar tools creating remote services for lateral movement. IOCs: PSEXESVC service creation, admin share connections followed by service creation. Related MITRE: T1021.002, T1569."},
    {"id": "DR006", "name": "Web Shell Activity",
     "description": "Web server process spawning command shell or scripting interpreter, indicating web shell execution. IOCs: apache/nginx/iis spawning cmd.exe, PowerShell, or bash. Related MITRE: T1505.003."},
    {"id": "DR007", "name": "Mass File Encryption Pattern",
     "description": "High rate of file modification or renaming across multiple directories, indicative of ransomware encryption. Threshold: 100+ file changes in 30 seconds. Related MITRE: T1486."},
    {"id": "DR008", "name": "DNS Tunneling Detection",
     "description": "Unusually high volume of DNS queries or DNS queries with long subdomains (>50 chars), potential DNS data exfiltration. Related MITRE: T1071.004, T1048.003, T1572."},
    {"id": "DR009", "name": "Privilege Escalation via Sudo",
     "description": "User executing sudo commands on Linux systems, especially to gain root access or run unusual commands. Related MITRE: T1548.003, T1068."},
    {"id": "DR010", "name": "Network Port Scan Detection",
     "description": "Single host making connection attempts to many different ports or IPs in short time, indicative of network reconnaissance. Related MITRE: T1046."},
    {"id": "DR011", "name": "Scheduled Task Creation",
     "description": "New scheduled task creation detected, commonly used for persistence. IOCs: schtasks /create, at commands, Task Scheduler event ID 4698. Related MITRE: T1053."},
    {"id": "DR012", "name": "Registry Run Key Persistence",
     "description": "Modification to Windows registry autorun keys HKLM/HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run. Related MITRE: T1547.001."},
    {"id": "DR013", "name": "UAC Bypass Attempt",
     "description": "Known UAC bypass techniques detected: fodhelper, eventvwr, sdclt abuse. Related MITRE: T1548.002."},
    {"id": "DR014", "name": "Pass-the-Hash Attack",
     "description": "NTLM authentication patterns consistent with pass-the-hash attack: authentication using hash without plaintext password. Related MITRE: T1550.002."},
    {"id": "DR015", "name": "Data Exfiltration over HTTP",
     "description": "Large data transfer via HTTP/HTTPS to external IPs not previously seen, potential data exfiltration. Related MITRE: T1041, T1048, T1567."},
]

# ── Hardcoded SOC response procedures ───────────────────────────

SOC_RESPONSE_PROCEDURES = [
    {
        "id": "RP001",
        "name": "Phishing Email Response Procedure",
        "content": (
            "1. Quarantine the reported email and all copies across mail gateways. "
            "2. Identify all recipients using message-trace tools. "
            "3. Check if any recipient clicked links or opened attachments — correlate with proxy/endpoint logs. "
            "4. If payload executed: isolate affected endpoints immediately. "
            "5. Extract IOCs (URLs, hashes, sender domains) and block in email gateway, proxy, and EDR. "
            "6. Reset credentials for any user who entered credentials on a phishing page. "
            "7. Notify affected users and their managers. "
            "8. Submit phishing sample to threat intel feeds. "
            "9. Document timeline and update playbook with new IOC patterns. "
            "Related MITRE: T1566, T1078, T1204."
        ),
    },
    {
        "id": "RP002",
        "name": "Ransomware Incident Response Procedure",
        "content": (
            "1. Immediately isolate infected hosts from the network — disable NICs or move to quarantine VLAN. "
            "2. Identify the ransomware family via file extension, ransom note, and hash lookups (ID Ransomware, VirusTotal). "
            "3. Determine patient zero and initial infection vector. "
            "4. Assess backup integrity — verify ransomware did not reach backup systems. "
            "5. Identify lateral movement scope — how many hosts affected. "
            "6. Notify leadership and legal as per IR plan. "
            "7. Engage law enforcement if warranted. "
            "8. Do NOT pay ransom without legal and executive approval. "
            "9. Restore from clean backups after re-imaging affected systems. "
            "10. Implement detection rules for specific ransomware TTPs. "
            "Related MITRE: T1486, T1490, T1489, T1059."
        ),
    },
    {
        "id": "RP003",
        "name": "Credential Compromise Response Procedure",
        "content": (
            "1. Immediately disable or reset compromised account credentials. "
            "2. Invalidate all active sessions and OAuth tokens for the account. "
            "3. Enable MFA if not already configured. "
            "4. Review account activity for the past 30 days — look for privilege escalation, data access, forwarding rules. "
            "5. Check for persistence mechanisms: new OAuth apps, inbox rules, forwarding, new admin accounts. "
            "6. Determine how credentials were obtained: phishing, credential stuffing, password spray, malware. "
            "7. Check for lateral movement using the compromised account. "
            "8. Notify the user and require password change across all systems. "
            "9. Block source IPs used by attacker. "
            "Related MITRE: T1078, T1110, T1539, T1552."
        ),
    },
    {
        "id": "RP004",
        "name": "Malware/Endpoint Compromise Response Procedure",
        "content": (
            "1. Isolate the endpoint immediately — disconnect from network, disable Wi-Fi. "
            "2. Capture memory dump and disk image for forensic analysis before remediation. "
            "3. Identify the malware family — run hash against VirusTotal, sandbox detonation. "
            "4. Collect forensic artifacts: prefetch, event logs, registry hives, scheduled tasks, startup entries. "
            "5. Identify persistence mechanisms and lateral movement attempts. "
            "6. Extract IOCs and hunt across all endpoints using EDR. "
            "7. Scope the incident — identify all affected systems. "
            "8. Re-image the endpoint; do not attempt disinfection in place. "
            "9. Restore from backup or rebuild with hardened baseline image. "
            "10. Update EDR/AV signatures with extracted IOCs. "
            "Related MITRE: T1055, T1547, T1543, T1036."
        ),
    },
    {
        "id": "RP005",
        "name": "Data Exfiltration Response Procedure",
        "content": (
            "1. Identify the exfiltration channel: HTTP/S, DNS, email, cloud storage, FTP. "
            "2. Block outbound connections to the destination IPs/domains immediately. "
            "3. Quantify data exfiltrated — review DLP alerts, proxy logs, email gateway logs. "
            "4. Determine what data was exfiltrated — classify sensitivity (PII, IP, credentials). "
            "5. Identify the source host and user account involved. "
            "6. Preserve logs and evidence for forensic and legal purposes. "
            "7. Notify legal, privacy, and compliance teams — assess breach notification requirements. "
            "8. Engage law enforcement if sensitive data or regulated data is involved. "
            "9. Notify affected individuals if PII was exfiltrated per applicable regulations. "
            "Related MITRE: T1041, T1048, T1567, T1071."
        ),
    },
    {
        "id": "RP006",
        "name": "Insider Threat Response Procedure",
        "content": (
            "1. Treat investigation with strict need-to-know — do not alert the subject. "
            "2. Preserve all evidence without tipping off the subject. "
            "3. Collect logs: DLP alerts, email, file access, badge access, VPN logs. "
            "4. Coordinate with HR and Legal before taking any action against the employee. "
            "5. Conduct covert monitoring only as authorized by legal counsel. "
            "6. Document the timeline of suspicious activities. "
            "7. Assess data accessed, copied, or exfiltrated. "
            "8. When ready to act: simultaneously disable access, recover assets, conduct interview with HR/Legal present. "
            "9. Preserve chain of custody for all digital evidence. "
            "Related MITRE: T1078, T1005, T1074, T1048."
        ),
    },
    {
        "id": "RP007",
        "name": "DDoS/Availability Attack Response Procedure",
        "content": (
            "1. Confirm attack type: volumetric, protocol, or application-layer DDoS. "
            "2. Engage upstream ISP or CDN provider DDoS mitigation services immediately. "
            "3. Activate DDoS scrubbing center or null-route attack traffic if available. "
            "4. Implement rate limiting and geo-blocking on edge firewalls. "
            "5. Enable WAF rules to filter application-layer attack patterns. "
            "6. Communicate status to stakeholders and affected users. "
            "7. Monitor for follow-on attacks that may use the DDoS as a distraction. "
            "8. Capture attack traffic samples for analysis and ISP reporting. "
            "9. Post-incident: implement BCP/DRP improvements and upstream mitigation agreements. "
            "Related MITRE: T1499, T1498."
        ),
    },
    {
        "id": "RP008",
        "name": "Privilege Escalation Response Procedure",
        "content": (
            "1. Identify the account that escalated privileges and the mechanism used. "
            "2. Revoke elevated privileges immediately; reset credentials. "
            "3. Determine what actions were taken with elevated access. "
            "4. Check for persistence installed while elevated (new accounts, services, scheduled tasks, backdoors). "
            "5. Audit all privileged account activity for the past 72 hours. "
            "6. Patch the vulnerability or misconfiguration exploited for escalation. "
            "7. Review and tighten sudo rules, UAC settings, or RBAC permissions. "
            "8. Hunt for similar escalation attempts across other endpoints. "
            "9. Verify integrity of critical system files and security tools. "
            "Related MITRE: T1548, T1134, T1068, T1053."
        ),
    },
    {
        "id": "RP009",
        "name": "Lateral Movement Containment Procedure",
        "content": (
            "1. Identify source and destination hosts involved in lateral movement. "
            "2. Isolate all confirmed compromised hosts from the network. "
            "3. Block the specific techniques used: disable SMB shares, restrict WMI/WinRM, block PsExec. "
            "4. Reset credentials for all accounts used in lateral movement — assume all touched accounts are compromised. "
            "5. Audit active sessions and forcibly terminate suspicious remote sessions. "
            "6. Segment the network to limit further spread — implement emergency VLAN changes if needed. "
            "7. Hunt across the environment for additional footholds using same TTPs. "
            "8. Review jump host and PAM logs for unauthorized use. "
            "9. Update EDR detection for the specific lateral movement technique observed. "
            "Related MITRE: T1021, T1550, T1534, T1210."
        ),
    },
    {
        "id": "RP010",
        "name": "Cloud Account Compromise Response Procedure",
        "content": (
            "1. Immediately revoke compromised IAM credentials (access keys, service account tokens). "
            "2. Review CloudTrail / Azure Activity Log / GCP Audit Log for all actions taken with the compromised credentials. "
            "3. Identify resources created, modified, or accessed by the attacker. "
            "4. Check for persistence: new IAM users/roles, new access keys, Lambda backdoors, new cloud resources. "
            "5. Revoke all sessions associated with the compromised identity. "
            "6. Assess data access: S3 buckets, storage blobs, databases accessed or exfiltrated. "
            "7. Terminate any attacker-created compute instances (crypto miners are common). "
            "8. Enable MFA enforcement for all privileged cloud accounts. "
            "9. Review and tighten IAM policies — apply least privilege. "
            "10. Enable GuardDuty/Defender for Cloud/Security Command Center for ongoing monitoring. "
            "Related MITRE: T1078, T1552, T1530, T1537."
        ),
    },
]


class KnowledgeIngestionService:
    def __init__(self):
        self.qdrant_url  = os.getenv("QDRANT_URL", "http://qdrant:6333")
        self.collection  = "socpilots_knowledge"

        self.thehive_url = (os.getenv("THEHIVE_URL", "")).rstrip("/")
        self.thehive_key = os.getenv("THEHIVE_API_KEY", "")

        self.opensearch_url  = (os.getenv("OPENSEARCH_URL", "")).rstrip("/")
        self.opensearch_user = os.getenv("OPENSEARCH_USER", "admin")
        self.opensearch_pass = os.getenv("OPENSEARCH_PASS", "")
        self.wazuh_index     = os.getenv("WAZUH_INDEX", "wazuh-alerts-*")

        log.info("Loading sentence-transformers model BAAI/bge-small-en-v1.5…")
        self.model = SentenceTransformer("BAAI/bge-small-en-v1.5")
        log.info("Embedding model ready — 384 dimensions")

        self.client = QdrantClient(url=self.qdrant_url)

    def _embed(self, text: str) -> list[float]:
        """Embed a document (not a query) — no prefix needed for BGE documents."""
        return self.model.encode(text, normalize_embeddings=True).tolist()

    @staticmethod
    def _point_id(item_id: str) -> int:
        """Convert a string item_id to a stable uint64 Qdrant point ID."""
        return abs(hash(item_id)) % (2 ** 63)

    def setup_vector_index(self) -> None:
        """Create Qdrant collection 'socpilots_knowledge' (idempotent)."""
        try:
            self.client.create_collection(
                collection_name=self.collection,
                vectors_config=VectorParams(size=384, distance=Distance.COSINE),
            )
            log.info(f"Qdrant collection '{self.collection}' created")
        except Exception as e:
            # Collection already exists — this is expected on re-runs
            err = str(e).lower()
            if "already exists" in err or "conflict" in err:
                log.info(f"Qdrant collection '{self.collection}' already exists — skipping creation")
            else:
                log.warning(f"Collection setup warning: {e}")

    def _upsert_knowledge_item(
        self,
        item_id: str,
        title: str,
        description: str,
        item_type: str,
        source: str,
        metadata: dict,
    ) -> None:
        text_for_embedding = f"{title}. {description}"
        embedding = self._embed(text_for_embedding)
        point_id  = self._point_id(item_id)

        payload = {
            "id":         item_id,
            "title":      title,
            "content":    description,
            "type":       item_type,
            "source":     source,
            "metadata":   metadata,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }

        self.client.upsert(
            collection_name=self.collection,
            points=[
                PointStruct(
                    id=point_id,
                    vector=embedding,
                    payload=payload,
                )
            ],
        )

    # ── Phase 1: MITRE ATT&CK ─────────────────────────────────

    def ingest_mitre_attack_patterns(self) -> int:
        count = 0
        for t in MITRE_TECHNIQUES:
            self._upsert_knowledge_item(
                item_id=f"mitre:{t['id']}",
                title=f"{t['id']} — {t['name']}",
                description=f"Tactic: {t['tactic']}. {t['description']}",
                item_type="AttackPattern",
                source="mitre",
                metadata={"technique_id": t["id"], "tactic": t["tactic"], "name": t["name"]},
            )
            count += 1
        log.info(f"Ingested {count} MITRE ATT&CK techniques")
        return count

    # ── Phase 2: Detection Rules ──────────────────────────────

    def ingest_detection_rules(self) -> int:
        count = 0

        # Built-in SOC rules
        for rule in SOC_DETECTION_RULES:
            self._upsert_knowledge_item(
                item_id=f"rule:{rule['id']}",
                title=rule["name"],
                description=rule["description"],
                item_type="DetectionRule",
                source="soc_rules",
                metadata={"rule_id": rule["id"]},
            )
            count += 1

        # Wazuh rules via OpenSearch aggregation
        if self.opensearch_url:
            try:
                resp = requests.post(
                    f"{self.opensearch_url}/{self.wazuh_index}/_search",
                    auth=(self.opensearch_user, self.opensearch_pass),
                    verify=False,
                    timeout=15,
                    json={
                        "size": 0,
                        "aggs": {
                            "rules": {
                                "terms": {"field": "rule.id", "size": 200,
                                          "order": {"doc_count": "desc"}},
                                "aggs": {
                                    "desc":   {"terms": {"field": "rule.description", "size": 1}},
                                    "level":  {"max":   {"field": "rule.level"}},
                                    "groups": {"terms": {"field": "rule.groups", "size": 3}},
                                },
                            }
                        },
                    },
                )
                buckets = resp.json().get("aggregations", {}).get("rules", {}).get("buckets", [])
                for b in buckets[:100]:
                    rule_id = b["key"]
                    desc    = b.get("desc", {}).get("buckets", [{}])[0].get("key", "")
                    level   = int(b.get("level", {}).get("value") or 0)
                    groups  = [g["key"] for g in b.get("groups", {}).get("buckets", [])]
                    if not desc:
                        continue
                    self._upsert_knowledge_item(
                        item_id=f"wazuh_rule:{rule_id}",
                        title=f"Wazuh Rule {rule_id} (level {level})",
                        description=f"Detection: {desc}. Groups: {', '.join(groups)}.",
                        item_type="DetectionRule",
                        source="wazuh",
                        metadata={
                            "rule_id": rule_id,
                            "level":   level,
                            "groups":  groups,
                            "count":   b.get("doc_count", 0),
                        },
                    )
                    count += 1
                log.info(f"Ingested {len(buckets[:100])} Wazuh rules from OpenSearch")
            except Exception as e:
                log.warning(f"Wazuh rule ingestion failed: {e}")

        return count

    # ── Phase 3: Historical Incidents from TheHive ────────────

    def ingest_historical_incidents(self) -> int:
        if not self.thehive_url or not self.thehive_key:
            log.warning("TheHive not configured — skipping incident ingestion")
            return 0
        count = 0
        try:
            resp = requests.post(
                f"{self.thehive_url}/api/v1/query",
                headers={
                    "Authorization": f"Bearer {self.thehive_key}",
                    "Content-Type":  "application/json",
                },
                verify=False,
                timeout=20,
                json={"query": [
                    {"_name": "listCase"},
                    {"_name": "sort", "_fields": [{"_createdAt": "desc"}]},
                    {"_name": "page", "from": 0, "to": 200},
                ]},
            )
            cases = resp.json() if isinstance(resp.json(), list) else []
            for c in cases:
                title = c.get("title", "")
                desc  = c.get("description", "") or ""
                if not title:
                    continue
                sev_map = {1: "Low", 2: "Medium", 3: "High", 4: "Critical"}
                sev  = sev_map.get(c.get("severity", 2), "Medium")
                text = f"{title}. Severity: {sev}. Status: {c.get('status', '')}. {desc[:500]}"
                self._upsert_knowledge_item(
                    item_id=f"thehive:{c.get('_id', title[:30])}",
                    title=f"[{sev}] {title}",
                    description=text,
                    item_type="IncidentCase",
                    source="thehive",
                    metadata={
                        "case_id":    c.get("caseId"),
                        "severity":   sev,
                        "status":     c.get("status"),
                        "tags":       c.get("tags", []),
                        "created_at": c.get("_createdAt"),
                    },
                )
                count += 1
            log.info(f"Ingested {count} TheHive incidents")
        except Exception as e:
            log.warning(f"TheHive incident ingestion failed: {e}")
        return count

    # ── Phase 4: Post-Incident Reports from TheHive ───────────

    def ingest_incident_reports(self) -> int:
        """
        Ingest post-incident analysis from resolved TheHive cases tagged with
        'post-incident' or 'lessons-learned'. Item type: IncidentReport.
        """
        if not self.thehive_url or not self.thehive_key:
            log.warning("TheHive not configured — skipping incident report ingestion")
            return 0
        count = 0
        try:
            resp = requests.post(
                f"{self.thehive_url}/api/v1/query",
                headers={
                    "Authorization": f"Bearer {self.thehive_key}",
                    "Content-Type":  "application/json",
                },
                verify=False,
                timeout=20,
                json={"query": [
                    {"_name": "listCase"},
                    {
                        "_name": "filter",
                        "_field": "status",
                        "_value": "Resolved",
                    },
                    {"_name": "sort", "_fields": [{"_createdAt": "desc"}]},
                    {"_name": "page", "from": 0, "to": 500},
                ]},
            )
            cases = resp.json() if isinstance(resp.json(), list) else []
            for c in cases:
                tags = [str(t).lower() for t in c.get("tags", [])]
                if not any(tag in tags for tag in ("post-incident", "lessons-learned")):
                    continue
                title = c.get("title", "")
                desc  = c.get("description", "") or ""
                if not title:
                    continue
                sev_map = {1: "Low", 2: "Medium", 3: "High", 4: "Critical"}
                sev = sev_map.get(c.get("severity", 2), "Medium")
                text = (
                    f"Post-Incident Report: {title}. "
                    f"Severity: {sev}. Status: {c.get('status', '')}. "
                    f"Tags: {', '.join(c.get('tags', []))}. "
                    f"{desc[:800]}"
                )
                self._upsert_knowledge_item(
                    item_id=f"report:thehive:{c.get('_id', title[:30])}",
                    title=f"[PostIncident/{sev}] {title}",
                    description=text,
                    item_type="IncidentReport",
                    source="thehive_reports",
                    metadata={
                        "case_id":    c.get("caseId"),
                        "severity":   sev,
                        "status":     c.get("status"),
                        "tags":       c.get("tags", []),
                        "created_at": c.get("_createdAt"),
                    },
                )
                count += 1
            log.info(f"Ingested {count} post-incident reports from TheHive")
        except Exception as e:
            log.warning(f"TheHive incident report ingestion failed: {e}")
        return count

    # ── Phase 5: SOC Response Procedures ─────────────────────

    def ingest_response_procedures(self) -> int:
        """Ingest hardcoded SOC response procedures."""
        count = 0
        for proc in SOC_RESPONSE_PROCEDURES:
            self._upsert_knowledge_item(
                item_id=f"procedure:{proc['id']}",
                title=proc["name"],
                description=proc["content"],
                item_type="ResponseProcedure",
                source="soc_procedures",
                metadata={"procedure_id": proc["id"]},
            )
            count += 1
        log.info(f"Ingested {count} SOC response procedures")
        return count

    # ── Orchestration ─────────────────────────────────────────

    def run_ingestion(self, sources: list[str] | None = None) -> dict:
        """
        Orchestrate knowledge base ingestion.
        sources: list of 'mitre' | 'rules' | 'incidents' | 'incident_reports' | 'response_procedures'
        """
        if sources is None:
            sources = ["mitre", "rules", "incidents", "incident_reports", "response_procedures"]
        log.info(f"Starting ingestion for sources: {sources}")
        self.setup_vector_index()

        mitre              = self.ingest_mitre_attack_patterns() if "mitre"              in sources else 0
        rules              = self.ingest_detection_rules()        if "rules"              in sources else 0
        incidents          = self.ingest_historical_incidents()   if "incidents"          in sources else 0
        incident_reports   = self.ingest_incident_reports()       if "incident_reports"   in sources else 0
        response_procs     = self.ingest_response_procedures()    if "response_procedures" in sources else 0

        total = mitre + rules + incidents + incident_reports + response_procs
        log.info(f"Ingestion complete — {total} items total")
        return {
            "mitre_techniques":       mitre,
            "detection_rules":        rules,
            "historical_incidents":   incidents,
            "incident_reports":       incident_reports,
            "response_procedures":    response_procs,
            "total":                  total,
        }

    def get_stats(self) -> dict:
        """Return per-type point counts from Qdrant."""
        ITEM_TYPES = [
            "AttackPattern",
            "DetectionRule",
            "IncidentCase",
            "IncidentReport",
            "ResponseProcedure",
        ]
        stats: dict[str, int] = {}
        for itype in ITEM_TYPES:
            try:
                result = self.client.count(
                    collection_name=self.collection,
                    count_filter=Filter(
                        must=[FieldCondition(key="type", match=MatchValue(value=itype))]
                    ),
                    exact=True,
                )
                stats[itype] = result.count
            except Exception as e:
                log.warning(f"Could not count type {itype}: {e}")
                stats[itype] = 0

        try:
            info = self.client.get_collection(self.collection)
            stats["total"] = info.points_count or sum(stats.values())
        except Exception:
            stats["total"] = sum(stats.values())

        return stats

    def close(self) -> None:
        # QdrantClient manages its own connection pool; no explicit close needed.
        pass
