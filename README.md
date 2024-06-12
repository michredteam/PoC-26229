# PoC-26229

CVE-2024-26229 is a high-severity vulnerability in the Windows Client-Side Caching (CSC) service, also known as the Offline Files service. This vulnerability allows local attackers to elevate their privileges on a system, potentially gaining full control over affected devices.

![ezgif-6-1ff611c00f](https://github.com/michredteam/PoC-26229/assets/168865716/f74857ac-ceec-4114-ab23-b731acdf9d16)

## Details of the Vulnerability
Nature: The issue is related to how the CSC service handles file operations and permissions. Specifically, it involves improper management of file access permissions, which can be exploited through symbolic links (symlinks)​ (NVD)​​ (CVE CyberSecurity Database News)​.
Impact: If successfully exploited, an attacker can gain elevated privileges, allowing them to access, modify, or delete critical system files, or execute malicious code​ (MSRC)​​ (NVD)​.
Severity: The vulnerability has a CVSS v3.1 base score of 7.8, indicating a high level of risk​ (NVD)​.
## Exploitation Details
Attackers need local access to the target system.
The exploitation involves creating a symlink between a targeted file and a file or folder the attacker can control. This could be used to manipulate system files or execute code with elevated privileges​ (CVE CyberSecurity Database News)​.
## Affected Systems
The vulnerability affects several versions of Windows, including:

Windows 10: Versions 1607, 1809, 21H2, and 22H2.
Windows 11: Versions 21H2, 22H2, and 23H2.
Windows Server: 2008, 2012, 2016, 2019, and 2022​ (SecAlerts)​.
## Mitigation and Solutions
Patch: Microsoft has released patches for affected versions. Users should ensure their systems are updated with the latest security patches to mitigate this vulnerability. Relevant updates can be found on Microsoft's Security Update Guide​ (Rapid7)​​ (CVE.org)​.
Best Practices: In addition to applying patches, implementing the principle of least privilege, regularly reviewing user permissions, and monitoring system activity can help mitigate risks associated with privilege escalation vulnerabilities​ (CVE CyberSecurity Database News)​​ (SecAlerts)​.

## patches
The CVE-2024-26229 vulnerability in the Windows Client-Side Caching (CSC) service, which allows for privilege escalation, has been patched by Microsoft through several updates. Here are the specific patches for different Windows versions:

Windows 10:

Versions 1607, 1809, 21H2, 22H2:
Patch: KB5036892​ (CVE CyberSecurity Database News)​​ (SecAlerts)​.
Windows 11:

Versions 21H2, 22H2, 23H2:
Patch: KB5036893​ (Rapid7)​​ (SecAlerts)​.
Windows Server:

Server 2012, 2012 R2, 2016:
Patch: KB5036896​ (CVE CyberSecurity Database News)​​ (SecAlerts)​.
Server 2019, 2022:
Patch: KB5036899​ (Rapid7)​​ (CVE CyberSecurity Database News)​.

## Still Vulnerable Versions
The vulnerability remains in systems that have not applied these updates. Specifically, the following versions are still vulnerable if they have not received the mentioned patches:

Windows 10: Any version without KB5036892.
Windows 11: Any version without KB5036893.
Windows Server: Any version without KB5036896 or KB5036899, depending on the specific server version​ (CVE CyberSecurity Database News)​​ (SecAlerts)​.
## How to Verify and Update
To ensure your system is patched:

Windows Update:
Go to Settings > Update & Security > Windows Update.
Click Check for updates to ensure your system is current.
Microsoft Update Catalog:
Search for the KB numbers mentioned to manually download and install the patches.

## Additional References
Microsoft Security Update Guide for CVE-2024-26229
NVD NIST CVE-2024-26229 Details
Rapid7 Analysis on CVE-2024-26229
