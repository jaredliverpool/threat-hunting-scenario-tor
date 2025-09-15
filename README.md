<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/jaredliverpool/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md) 

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for the DeviceFileEvents table for ANY file that had the string “tor” in it and discovered what looks like the user “employee” downloaded a tor installer, did something that resulted in many tor-related files being copied to the desktop and the creation of a file called “tor-shopping-list.txt” on the desktop. These events began at: 2025-09-15T17:11:29.7482048Z.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "jared-threat-hu"
| where InitiatingProcessAccountName  == "labuser"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-09-15T16:51:00.3533257Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```

<img width="1673" height="541" alt="Screenshot 2025-09-15 at 2 55 37 PM" src="https://github.com/user-attachments/assets/988e1485-b881-4b92-9d4f-e881fc0e1957" />


---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for any ProcessCommandLine that contained the string “tor-browser-windows-x86_64-portable-14.5.6.exe”. Based on the logs returned at 2025-09-15T16:53:21.6757036Z, on the computer named jared-threat-hu, a user account called “labuser” launched the file tor-browser-windows-x86_64-portable-14.5.6.exe, which was located in C:\Users\labuser\Downloads. 

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "jared-threat-hu"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.6.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1664" height="102" alt="Screenshot 2025-09-15 at 2 58 13 PM" src="https://github.com/user-attachments/assets/459ddae1-b198-4030-8bd3-b9133a707a65" />


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for any indication that user “labuser” actually opened the tor browser. There was evidence that they did open it at 2025-09-15T16:54:50.6257532Z. There were several other instances of firefox.exe (Tor) as well as tor.exe spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "jared-threat-hu"
| where FileName has_any ("tor-browser-windows-x86_64-portable-<version>.exe", "torbrowser-install-win64-<version>_ALL.exe", "firefox.exe", "tor.exe")
| project Timestamp,DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```
<img width="1681" height="851" alt="Screenshot 2025-09-15 at 2 59 20 PM" src="https://github.com/user-attachments/assets/7b297288-ce14-4815-8e62-935ed70b8edd" />


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the DeviceNetworkEvents table for any indication the tor browser was used to establish connection using any of the known ports 2025-09-15T16:54:52.029213Z, the user labuser on device jared-threat-hu made a successful network connection. The process firefox.exe. Running from c:\users\labuser\desktop\tor browser\browser\firefox.exe. Connected to 127.0.0.1 on port 9151. There were a few other connections.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "jared-threat-hu"
| where InitiatingProcessAccountName != "system"
| where RemotePort in ("9001","9030","9040","9050","9051","9150","9151")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```
<img width="1682" height="291" alt="Screenshot 2025-09-15 at 3 00 28 PM" src="https://github.com/user-attachments/assets/ead45911-0200-4239-a9c8-4ac580a406ca" />


---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-09-15 16:53:21.6757036Z`
- **Event:** The user labuser launched the file tor-browser-windows-x86_64_portable-14.5.6.exe from the Downloads folder. This is the Tor Browser installer / portable version.
- **Action:** File download detected.
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64_portable-14.5.6.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-09-15 16:54:50.6257532Z`
- **Event:** Evidence that labuser opened (ran) Tor Browser: firefox.exe (which is the Tor Browser’s front-end) executed, and later tor.exe processes spawned.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64_portable-14.5.6.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-09-15 16:54:52.029213Z`
- **Event:** UThe process firefox.exe running from the Tor Browser folder c:\users\labuser\desktop\tor browser\browser\firefox.exe made a successful connection to 127.0.0.1 on port 9151. This is the ControlPort that Tor Browser uses to communicate between firefox.exe and tor.exe.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `c:\users\labuser\desktop\tor browser\browser\firefox.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2024-11-08T22:18:01.1246358Z`
- **Event:** A network connection to IP `176.198.159.33` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-09-15 17:11:29.7482048Z`
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2024-11-08T22:27:19.7259964Z`
- **Event:** Earlier in the hunt you observed that at this time, files involving “tor” begin appearing: the installer, copying of many tor-related files to the Desktop, and creation of a file named tor-shopping-list.txt on the desktop. This indicates user actions related to setting up or using Tor Browser.
- **Action:** File creation detected.
- **File Path:** `C:\Users\employee\Desktop\tor-shopping-list.txt`

---

## Summary

The user labuser downloaded a portable Tor Browser installer. Soon after, they launched it. Then, they executed firefox.exe from within a folder named “tor browser” on their Desktop (so likely they extracted/copied or moved it). The system shows firefox.exe connecting locally (127.0.0.1) on port 9151, which is the Tor Browser control interface (ControlPort) between the browser UI and the underlying Tor process. Also, many Tor-related files were copied to desktop and a file “tor-shopping-list.txt” appeared (possibly notes or configuration). So, everything points to the user having installed and used Tor Browser on that machine. The presence of ControlPort communications, process executions, copying of files, etc., make this more than just a downloaded file. Tor Browser was actually run.

---

## Response Taken

TOR usage was confirmed on endpoint jared-threat-hu. The device was isolated and the user's direct manager was notified.

---
