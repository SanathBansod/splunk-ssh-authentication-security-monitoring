# Windows Security Event ID Guide for SOC Analysts
### Beginner-to-Intermediate Blue Team Field Manual

> **Purpose:** Learn what important Windows events mean, where to find them, how to investigate them, how to search for them in a SIEM, and what to do next.
>
> This is an original learning guide written in simple English. It is designed for a home lab, defensive monitoring, interviews, and SOC portfolio practice.

---

## Table of Contents

1. [Start Here: What Is a Windows Event?](#1-start-here-what-is-a-windows-event)
2. [How to Read an Event](#2-how-to-read-an-event)
3. [Where Events Are Stored](#3-where-events-are-stored)
4. [Prepare a Safe Practice Lab](#4-prepare-a-safe-practice-lab)
5. [Authentication and Logon Events](#5-authentication-and-logon-events)
6. [User and Group Changes](#6-user-and-group-changes)
7. [Privileges and Process Execution](#7-privileges-and-process-execution)
8. [PowerShell and Script Activity](#8-powershell-and-script-activity)
9. [Services, Persistence, and System Changes](#9-services-persistence-and-system-changes)
10. [Windows Firewall and Network Events](#10-windows-firewall-and-network-events)
11. [File Shares and Object Access](#11-file-shares-and-object-access)
12. [Active Directory and Kerberos](#12-active-directory-and-kerberos)
13. [Event Log and Audit Policy Changes](#13-event-log-and-audit-policy-changes)
14. [Useful Sysmon Events](#14-useful-sysmon-events)
15. [Investigation Walkthroughs](#15-investigation-walkthroughs)
16. [SIEM Queries: Splunk SPL](#16-siem-queries-splunk-spl)
17. [SIEM Queries: Microsoft Sentinel KQL](#17-siem-queries-microsoft-sentinel-kql)
18. [SOC Triage Checklist](#18-soc-triage-checklist)
19. [Common Mistakes](#19-common-mistakes)
20. [Practice Tasks](#20-practice-tasks)
21. [Quick Reference Tables](#21-quick-reference-tables)
22. [Glossary](#22-glossary)
23. [Official References](#23-official-references)

---

## 1. Start Here: What Is a Windows Event?

Windows creates event records when something happens on a computer. Examples include a user signing in, a password being rejected, a process starting, a service being installed, or an audit log being cleared.

Think of a Windows computer as an office building:

- **User account:** A person's identity card.
- **Logon:** The person enters the building.
- **Privilege:** The rooms and actions that person is allowed to use.
- **Process:** A program running inside the building.
- **Windows Event Log:** The security camera and visitor book.
- **SIEM:** A central security room that collects records from many buildings and helps analysts find unusual activity.

An event is **evidence**, not a final verdict. For example, 4625 means a logon failed. It does not automatically mean an attacker tried to break in. A user may have typed the wrong password.

### Why SOC analysts need Event IDs

A SOC analyst uses events to answer five questions:

1. **What happened?** Example: a logon failed.
2. **When did it happen?** Use the event timestamp and time zone.
3. **Where did it happen?** Identify the computer and source address, if available.
4. **Which identity or program was involved?** Check the account, process, logon ID, and related fields.
5. **What should happen next?** Check related activity, assess impact, and follow the incident-response process.

### Event ID vs. event name

An **Event ID** is a numeric identifier for an event type. The same ID may appear many times, once for every matching occurrence.

For example, Event ID **4625** is a failed logon. Ten records with ID 4625 mean ten recorded failed-logon events, not necessarily ten different users or ten different attackers.

### An important limitation

Windows does not record every security detail by default. The event available depends on the Windows version, audit policy, log channel, installed tools, and configuration. Some events appear only when a suitable audit setting is enabled. Missing events do not prove that an action did not happen.

---

## 2. How to Read an Event

Open an event in Event Viewer and review both the **General** tab and the **Details** tab.

| Field | Simple meaning | Analyst question |
|---|---|---|
| Log Name | Which log contains the record | Is this Security, System, or an application channel? |
| Source / Provider | Which Windows component wrote it | Which component reported the activity? |
| Event ID | Type of event | What does this ID represent? |
| Level | Information, Warning, Error, etc. | Does the level help explain a system problem? It is not the same as attack severity. |
| Time Created | When the event was recorded | What was happening around that time? |
| Computer | Host that recorded the event | Was this the endpoint, server, or domain controller? |
| Subject | Identity that requested an action | Who or what initiated the activity? |
| Target Account | Account affected by the action | Which identity was signed in to or changed? |
| Logon ID | Identifier used to link related events on a host | What else happened in this logon session? |
| Process Name | Program associated with an event | Is the path expected? |
| Source Network Address | Address Windows recorded as the source | Does it match the user's normal device or network? |
| Status / SubStatus | More detail about success or failure | Why did an authentication attempt fail? |

### Subject vs. target account

These are not always the same person.

For a password reset event, the **Subject** may be the administrator performing the reset, while the **Target Account** is the user whose password was reset. This distinction is important during investigations.

### Logon ID

A Logon ID is useful for connecting records from one Windows host. If a 4624 record has a Logon ID, other events on that host may show the same ID. It is not a universal ID shared across every computer.

### Time

Use UTC or a clearly stated time zone when building a timeline. SIEM ingestion time may be different from the event's original creation time. Check the actual timestamp field used by the data source.

### A repeatable reading method

For each event:

1. Read the event description.
2. Record the host and exact time.
3. Identify the subject and target.
4. Read the outcome and supporting fields.
5. Search nearby events before and after it.
6. Compare the activity with a known-good baseline.
7. Save evidence and explain your conclusion.

---

## 3. Where Events Are Stored

### Main Windows logs

| Log | What it commonly contains | Where to look |
|---|---|---|
| **Security** | Logons, account changes, privileges, object access, audit changes | Event Viewer → Windows Logs → Security |
| **System** | Service changes, startup/shutdown events, driver and system-component messages | Event Viewer → Windows Logs → System |
| **Application** | Events written by applications | Event Viewer → Windows Logs → Application |
| **PowerShell/Operational** | PowerShell engine and script-block logging events | Applications and Services Logs → Microsoft → Windows → PowerShell → Operational |
| **Windows Defender/Operational** | Microsoft Defender detection and protection activity | Applications and Services Logs → Microsoft → Windows → Windows Defender → Operational |
| **Sysmon/Operational** | Detailed process, network, file, registry, and other telemetry when Sysmon is installed and configured | Applications and Services Logs → Microsoft → Windows → Sysmon → Operational |

### Open Event Viewer

1. Press **Win + R**.
2. Type `eventvwr.msc`.
3. Press Enter.
4. Expand **Windows Logs**.
5. Select **Security**, **System**, or another log.
6. Choose **Filter Current Log** to filter by Event ID.
7. Open one result and inspect General and Details.

You may need administrator rights to read some logs.

### Search with PowerShell

Run PowerShell as an administrator if your account needs extra access:

```powershell
# Show the newest 20 Security log events with Event ID 4625
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id      = 4625
} -MaxEvents 20 |
Select-Object TimeCreated, Id, ProviderName, MachineName, Message
```

Another example:

```powershell
# Show recent account creation events
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id      = 4720
} -MaxEvents 20 |
Select-Object TimeCreated, Id, MachineName, Message
```

If no records are returned, do not immediately assume the activity never occurred. Check the time range, permissions, log retention, and audit policy.

---

## 4. Prepare a Safe Practice Lab

A beginner can start with one Windows 10 or Windows 11 virtual machine. A domain controller is useful for domain and Kerberos events, but it is not required for basic local-account events.

### Suggested setup

- One Windows VM (test endpoint).
- Event Viewer and PowerShell.
- Optional: Sysmon with a reviewed configuration.
- Optional: Splunk or Microsoft Sentinel training environment.
- A snapshot taken before making configuration changes.

### Safety rules

- Use a VM or a computer you are authorized to administer.
- Use a test account and test data.
- Do not generate password attempts against real accounts.
- Do not disable security controls on a production device.
- Restore the VM snapshot after experiments if needed.
- Never upload real usernames, public IPs, tokens, or sensitive event contents to a public repository.

### Audit policy matters

The local policy editor may be available on some Windows editions. Advanced audit policy can be reviewed under:

`Computer Configuration → Windows Settings → Security Settings → Advanced Audit Policy Configuration`

For a managed business device, coordinate changes with the system owner. Changing audit settings can increase log volume or change what is captured.

### Record your baseline

Before testing, write down:

- Windows version and hostname.
- Whether the device is domain-joined.
- Current time zone.
- Audit settings that are enabled.
- Log channels being collected.
- Whether Sysmon is installed.
- Your lab activity and the approximate test time.

This makes the result easier to understand later.

---

## 5. Authentication and Logon Events

These events help answer: **Who tried to access a system, from where, and did access succeed?**

### 4624 — An account was successfully logged on

**Simple meaning:** Windows recorded a successful logon.

**Why it matters:** It can help confirm access before or after suspicious activity. Review the logon type, account, source address, workstation, authentication package, and Logon ID.

**Useful fields:**
- TargetUserName / TargetDomainName
- LogonType
- IpAddress / WorkstationName
- TargetLogonId
- AuthenticationPackageName

**Common Logon Types**
| Type | Meaning in simple words | Investigation note |
|---:|---|---|
| 2 | Interactive logon | Often a local console sign-in |
| 3 | Network logon | Access through a network service; may be normal file or application access |
| 4 | Batch | A scheduled batch job |
| 5 | Service | A service starting under an account |
| 7 | Unlock | An existing session was unlocked |
| 8 | NetworkCleartext | Credentials were supplied in a way that may be represented as clear-text authentication at the package level; investigate context |
| 9 | NewCredentials | Alternate credentials were supplied for outbound connections |
| 10 | RemoteInteractive | Commonly Remote Desktop |
| 11 | CachedInteractive | Logon used cached domain credentials |

A logon type by itself is not proof of malicious activity. For example, type 3 appears frequently during normal Windows network operations.

**Triage steps**
1. Check the account and host.
2. Review the logon type.
3. Check the source address and time.
4. Compare with expected user behavior.
5. Look for nearby failed logons (4625), privilege events (4672), and process activity (4688) on that host.

### 4625 — An account failed to log on

**Simple meaning:** A sign-in attempt did not succeed.

**Why it matters:** A group of failures may reflect mistyped passwords, an outdated service password, password spraying, or brute-force attempts.

**Check:** Account name, source address, logon type, failure reason, Status, SubStatus, and time pattern.

**Triage steps**
1. Group failures by source, target account, and time window.
2. Check whether one source tried many accounts or one account received failures from many sources.
3. Check for a later successful 4624 event.
4. Look for lockout event 4740.
5. Validate whether the source belongs to a VPN, proxy, scanner, or approved management tool.
6. Escalate according to the alert rule and evidence.

A single failure is usually low-confidence evidence. Repeated failures followed by a successful sign-in may need higher priority.

### 4634 — An account was logged off

**Simple meaning:** A logon session ended.

**Why it matters:** Helps estimate the session period. It does not always mean the user deliberately clicked Sign out.

**Check:** Account, Logon ID, host, and nearby 4624 events. Correlate using the Logon ID on the same host.

### 4647 — User initiated logoff

**Simple meaning:** Windows recorded a user-initiated logoff.

**Why it matters:** Useful for timeline context. Do not treat it as an attack by itself.

### 4648 — A logon was attempted using explicit credentials

**Simple meaning:** A process or user tried to use credentials supplied explicitly rather than just the current logon context.

**Why it matters:** Can appear with legitimate administration, `runas`, scheduled tasks, and some lateral-movement investigations.

**Check:** Subject account, account whose credentials were used, process name, target server, and time. This event alone does not prove credential theft.

### 4740 — A user account was locked out

**Simple meaning:** The account reached a lockout condition.

**Why it matters:** It may follow repeated wrong passwords or an old password stored in a service, phone, or mapped drive.

**Triage steps**
1. Identify the locked account.
2. Examine 4625 events around the lockout time.
3. Check the caller computer name, if recorded.
4. Look for repeated activity from one host or multiple sources.
5. Confirm with the account owner before unlocking the account.

### 4767 — A user account was unlocked

**Simple meaning:** Windows recorded an account unlock action.

**Why it matters:** Check who unlocked the account and whether the unlock was part of the approved help-desk process.

### 4776 — Domain controller attempted to validate credentials (NTLM)

**Simple meaning:** Windows checked credentials using NTLM.

**Why it matters:** Helps investigate NTLM authentication failures and repeated credential validation. Review the account, source workstation, error code, and related logons.

### 4778 and 4779 — Remote session reconnect/disconnect

**Simple meaning:** A terminal-services session connected or disconnected.

**Why it matters:** Can add context to RDP or remote-session timelines. Pair with 4624 logon type 10, relevant host telemetry, and approved remote-access records.

### Authentication pattern examples

| Pattern | Possible explanation | Next check |
|---|---|---|
| Many 4625s for one user | Mistyped password, old stored password, or targeted guessing | Source host, time window, 4740 |
| Many 4625s for many users from one source | Password spraying or a misconfigured tool | Source ownership, rate, target list |
| 4625s followed by 4624 from the same source | Possible guessed password or a user finally entering the right password | Confirm account, sign-in origin, post-login activity |
| 4624 type 10 at an unusual time | Expected remote work or suspicious RDP | VPN, source IP, user confirmation, process activity |
| 4648 before remote access | Admin tool or possible alternate-credential use | Process, target host, account authorization |

---

## 6. User and Group Changes

These events help detect new accounts, password resets, disabled accounts, and unexpected privilege changes.

| Event ID | Meaning | Why a SOC analyst checks it |
|---:|---|---|
| **4720** | User account created | An unexpected account may provide access or persistence |
| **4722** | User account enabled | A disabled or dormant account became usable |
| **4723** | Attempt to change an account password | Shows a password-change attempt by an account context |
| **4724** | Attempt to reset an account password | Check who requested the reset and whose password was affected |
| **4725** | User account disabled | Could be expected offboarding or a suspicious attempt to disrupt access |
| **4726** | User account deleted | Verify change approval and asset ownership |
| **4738** | User account changed | Review changed fields and the actor |
| **4740** | User account locked out | Correlate with authentication failures |
| **4767** | User account unlocked | Verify the person or process responsible |
| **4728 / 4729** | Member added to / removed from a global security group | Check sensitive group membership changes in a domain |
| **4732 / 4733** | Member added to / removed from a local security group | Check local administrator and other privileged groups |
| **4756 / 4757** | Member added to / removed from a universal security group | Relevant in environments using universal groups |

### Event 4720 — New user account

**Questions to ask**
- Was account creation approved?
- Who created it?
- Is the account name meaningful or designed to resemble a normal account?
- Was it enabled, added to groups, or used to log on shortly afterward?
- Is the account interactive, a service account, or a test account?

**Investigation chain**
1. Find 4720 and record its subject and target.
2. Search for 4722, 4738, and group membership events for the target.
3. Search for 4624 events for the new account.
4. Review the host and time range.
5. Validate with the system owner or change ticket.

### Event 4728 / 4732 — Group membership changed

Membership changes can grant access to resources or administrative actions. The risk depends on which group was changed and what privileges it grants.

**Important:** Do not assume every group change is a privilege escalation. Confirm the group name and policy. For local machines, a group such as local Administrators is sensitive; domain environments also have high-impact domain groups.

**Investigation chain**
1. Identify the group and new member.
2. Identify who made the change.
3. Check whether the actor had approval.
4. Search for logons and sensitive actions by the added user.
5. If unauthorized, follow the change-control and incident process before removing membership.

### Event 4724 — Password reset attempt

Do not assume this event means the reset succeeded. Read the event result and related records. Verify the actor, target account, ticket, and subsequent authentication activity.

### Good detection idea

Alert on a **new user plus sensitive group membership plus an unusual successful logon** in a short period. Correlation gives more context than a single event. Tune the time window to the environment and avoid alerts from approved provisioning systems.

---

## 7. Privileges and Process Execution

### 4672 — Special privileges assigned to a new logon

**Simple meaning:** A logon received one or more sensitive privileges.

**Why it matters:** It can identify administrative or system-level sessions. It is common for expected services and administrators, so it is not automatically malicious.

**Check:** Account, host, Logon ID, privilege names, and matching 4624 event.

### 4688 — A new process was created

**Simple meaning:** Windows recorded that a new process started.

**Why it matters:** Process records help answer what ran, who launched it, and which parent process started it.

**Useful fields, depending on configuration:**
- New Process Name
- Creator / Parent Process Name
- Process ID and Creator Process ID
- Subject / Target account
- Process Command Line (may require a separate audit setting)

**What may look unusual?**
- A script interpreter launched from an unexpected parent.
- A command shell started by an office document or an unusual application.
- A process executed from a user-writable temporary folder.
- A process with an unexpected account, path, or time.
- A rare parent-child combination compared with the normal baseline.

These are investigation leads, not proof. Software installers, administrative scripts, and developer tools can create similar patterns.

**Triage steps**
1. Record the executable path, command line if present, parent, account, and time.
2. Confirm the executable's publisher and hash using approved tools.
3. Check whether the parent process is expected.
4. Search surrounding events for downloads, PowerShell use, new services, or network connections.
5. Compare with a clean baseline and business activity.
6. Escalate if the behavior is unexplained and the evidence supports risk.

### 4689 — A process exited

**Simple meaning:** A process ended.

**Use:** Add an ending time to a timeline. Process-exit auditing may need to be enabled and can produce high log volume.

### Process command-line logging

4688 may not include command-line text unless the appropriate audit policy is enabled. Configure this carefully, because command lines can contain sensitive arguments. Protect the logs and restrict access.

### Link process events

A useful process story can be:

`User logon → 4688 process start → script or tool activity → network or file events → process exit`

Do not rely on a single record if other telemetry is available.

---

## 8. PowerShell and Script Activity

PowerShell is a normal Windows administration tool. Attackers can also misuse it, which makes logging and context important.

### PowerShell event channels

Common PowerShell Operational events include:

| Event ID | Common use | Analyst note |
|---:|---|---|
| **400 / 403** | Engine state starts / stops in relevant PowerShell channels | Provides session timing context |
| **4103** | Module logging, when enabled | Can show command or pipeline activity |
| **4104** | Script block logging, when enabled | May record script text executed by PowerShell |

The exact fields and availability depend on PowerShell version and policy settings.

### How to investigate suspicious PowerShell

1. Find the PowerShell event and record the host, user, time, and script content if available.
2. Review the process that launched PowerShell (4688 or Sysmon Event 1).
3. Look for parent applications, downloaded files, network connections, and file writes.
4. Check whether the script is part of a signed, approved administration task.
5. Review nearby Defender alerts, DNS events, and remote logon activity.
6. Preserve relevant logs before making changes.

### Avoid simplistic rules

A search for a word like `EncodedCommand` or a hidden-window option can be a useful lead but can also find legitimate automation. A SOC rule should use context, such as unusual parent process, rare account, suspicious destination, or known malicious indicators. Do not run suspicious scripts simply to see what they do.

---

## 9. Services, Persistence, and System Changes

Windows services can start automatically and run in the background. This is normal for many applications, but an unexpected service can be important evidence.

| Event ID / Log | Meaning | Why investigate |
|---|---|---|
| **4697 (Security)** | A service was installed | Identify who installed it and which executable it uses |
| **7045 (System)** | A service was installed | Provides service name, image path, start type, and account details where available |
| **7036 (System)** | A service entered a running or stopped state | Helps build a service activity timeline |
| **7040 (System)** | A service start type changed | An unexpected change may affect persistence or security controls |
| **6005 (System)** | Event Log service started | Often used as a startup clue |
| **6006 (System)** | Event Log service stopped normally | Helps build shutdown timelines |
| **6008 (System)** | Previous shutdown was unexpected | May reflect a crash, power loss, or other issue; not automatically malicious |

### Service installation investigation

1. Record the service name, binary path, start type, service account, actor, and time.
2. Check whether the executable is in an expected application directory.
3. Verify file signature and hash using trusted tools.
4. Search for 4688 or Sysmon process events associated with the installer or binary.
5. Check if the installation matches a change ticket or software deployment.
6. Review service start events and subsequent activity.

### Watch-outs

- A service can be legitimate even if it is unfamiliar to a junior analyst.
- A familiar service name can be copied by an unwanted program.
- Event 4697 and 7045 are separate events from separate logs. Use both when available.
- Do not delete a service or remove files before preserving evidence and following the response process.

---

## 10. Windows Firewall and Network Events

### Firewall service and policy context

Event **5025** can indicate that the Windows Firewall service stopped. Other firewall and filtering events vary by the specific firewall auditing configuration. Validate the provider and full event message before mapping a number to a conclusion.

A firewall service stopping is important, but there may be a planned maintenance reason, a service issue, or a policy change.

### Windows Filtering Platform events

| Event ID | General meaning | SOC use |
|---:|---|---|
| **5156** | WFP permitted a connection | Connection telemetry, if the relevant auditing is enabled |
| **5157** | WFP blocked a connection | Investigate denied traffic in context |

These records may be noisy. Review direction, application path, source/destination addresses and ports, protocol, host role, and whether the connection was expected.

### Network investigation checklist

- Which process was involved?
- Which local and remote addresses and ports appear?
- Did DNS resolve the destination?
- Was the connection allowed or blocked?
- Is the destination normal for this machine?
- Did a suspicious process start immediately before the connection?
- Are there related alerts from Defender, Sysmon, proxy, DNS, or firewall logs?

Network events alone do not prove that data was stolen or malware was running.

---

## 11. File Shares and Object Access

| Event ID | Meaning | Why it matters |
|---:|---|---|
| **4656** | A handle to an object was requested | May show an access request; result and object type matter |
| **4663** | An attempt was made to access an object | Can help investigate access to sensitive files, if auditing is configured |
| **4657** | A registry value was modified | Useful for some registry-change investigations |
| **5140** | A network share was accessed | Shows access to a share, often useful for lateral-movement and data-access investigations |
| **5145** | A network share object was checked for requested access | Helps investigate share/file access requests, when detailed auditing is enabled |

### What 5140 can tell you

An access event for a share may be normal business activity. Check the account, source address, share name, host role, and time. Investigate whether the access is unusual for that user or computer.

### What 4663 can tell you

This event is useful only when auditing is configured for the relevant object and access. It does not mean every file read will always be logged. Object-access logging can create a lot of data, so select the right scope.

### File access investigation

1. Identify the object or share.
2. Check the account and source device.
3. Understand the requested access rights.
4. Compare with that account's normal work.
5. Correlate with successful logons, process execution, archive creation, and outbound network activity.
6. Follow the organization's privacy and incident-handling rules.

---

## 12. Active Directory and Kerberos

These events usually matter on domain controllers. A standalone home PC may not generate them in the same way.

### Kerberos quick explanation

Kerberos is a common way domain users and services prove identity. At a high level, a user gets a Ticket Granting Ticket (TGT), then asks for service tickets to access services. The event records can help show which identity requested tickets and when.

| Event ID | Common meaning | SOC investigation focus |
|---:|---|---|
| **4768** | Kerberos TGT requested | Account, client address, result code, encryption details, timing |
| **4769** | Kerberos service ticket requested | Account, service name, client address, ticket encryption, request volume |
| **4771** | Kerberos pre-authentication failed | Repeated failures, source host, account, and status |
| **4662** | An operation was performed on an Active Directory object | Requires suitable auditing and correct interpretation of object/access details |
| **5136** | A directory service object was modified | Review which directory object and attribute changed, actor, and change approval |
| **5137** | A directory service object was created | Review the new directory object and creator |
| **5141** | A directory service object was deleted | Confirm approved deletion and impact |

### Event 4768 — TGT request

Check the account, client address, result, encryption type, and time. A high number of requests may be normal during login bursts or could indicate unusual authentication activity. Baselines are important.

### Event 4769 — Service ticket request

High-volume service ticket requests may be a lead for Kerberoasting investigations, but volume alone is not enough. Review the targeted service accounts, ticket encryption type, source host, time range, and normal application behavior. Use established detections and current guidance rather than relying on one fixed threshold.

### Event 4771 — Kerberos pre-authentication failure

This may indicate a wrong password, an outdated credential, or repeated guessing. Correlate with other authentication events and investigate the source and target account.

### Event 5136 — Directory object modified

Review the changed object, modified attribute, subject, and before/after details when available. Confirm whether the change is approved. Some advanced directory abuse techniques may require particular object auditing and permissions to be visible; no single event is guaranteed to expose every technique.

### Domain-controller context

When investigating domain events:
1. Confirm which domain controller recorded the event.
2. Check the client address and account.
3. Compare events across relevant domain controllers.
4. Correct for time-zone and collection delays.
5. Correlate with endpoint logs from the originating workstation.
6. Avoid assuming one domain-controller event fully describes an entire user session.

---

## 13. Event Log and Audit Policy Changes

These events can matter because attackers may try to reduce visibility. They can also occur during approved maintenance.

| Event ID / Log | Meaning | Why it matters |
|---|---|---|
| **1102 (Security)** | Security audit log was cleared | Important signal that needs urgent validation |
| **104 (System)** | An event log was cleared | Check which log was cleared and by whom, where fields are available |
| **4719 (Security)** | System audit policy changed | A change could reduce or alter visibility |
| **4902 (Security)** | Per-user audit policy table created | Useful context for audit configuration changes |
| **4907 (Security)** | Auditing settings on an object changed | Check the target object and actor |

### Investigate a cleared log

1. Record the event, host, actor, and time.
2. Determine which log was cleared.
3. Check whether a maintenance ticket explains it.
4. Review centralized SIEM records, EDR telemetry, backups, and other hosts for the same timeframe.
5. Check nearby service, process, privilege, and logon activity.
6. Escalate promptly if the action is unexplained.

**Important:** If a local log is cleared, copies already forwarded to a SIEM may still exist. If there is no central collection, the available local evidence may be incomplete.

### Audit policy changed

Confirm which audit category changed and whether the change is authorized. A change that reduces successful/failed logon or process-creation auditing may leave the SOC with less evidence. Collect the policy-change record and compare it against the approved baseline.

---

## 14. Useful Sysmon Events

Sysmon is an optional Microsoft Sysinternals tool. It writes detailed telemetry to its own Operational log when installed and configured. Its event IDs are separate from Windows Security log IDs. Sysmon configuration controls what is recorded.

| Sysmon ID | Common meaning | Potential investigation use |
|---:|---|---|
| **1** | Process creation | Process tree, command line, hashes, parent/child details |
| **3** | Network connection | Link a process to a network destination, if enabled |
| **7** | Image loaded | Investigate unusual DLL/image loads; can be high-volume |
| **8** | CreateRemoteThread | Potential process-injection lead; review context |
| **10** | Process access | Investigate process-to-process access; can be noisy |
| **11** | File created | Locate newly created files |
| **12 / 13 / 14** | Registry object/value activity | Investigate selected registry changes |
| **22** | DNS query | Connect a process to queried domain names |
| **23 / 26** | File deletion events, depending on configuration/version | Investigate deletion or evidence-cleanup patterns |

A Sysmon event is not automatically malicious. For example, many applications create files, query DNS, and load DLLs. Use a consistent configuration, baseline normal behavior, and combine related records.

### Windows Security 4688 vs Sysmon 1

- **4688:** Windows Security process-creation auditing. Field detail depends on audit configuration.
- **Sysmon 1:** Sysmon process-creation telemetry, often including useful parent, command-line, hash, and process GUID details depending on version/configuration.

They complement each other; they are not interchangeable IDs.

---

## 15. Investigation Walkthroughs

These are example workflows for an isolated practice lab. They do not claim that an actual compromise occurred.

### Case A — Many failed logons

**Alert:** Multiple 4625 events for one or more accounts.

**Step 1 — Define the scope**
- Host(s)
- First and last event time
- Source addresses
- Target usernames
- Logon types and status codes

**Step 2 — Group events**
Determine whether one source is trying many accounts, or many sources are targeting one account.

**Step 3 — Search for outcomes**
Look for 4624 successes after the failures and for 4740 lockouts. Compare source, target, and timing.

**Step 4 — Validate**
Check VPN/proxy logs, approved scanners, scheduled services, and user reports.

**Step 5 — Rate the evidence**
Repeated failures alone may be suspicious but do not confirm access. A related unusual successful logon and unexplained post-login activity increases concern.

**Step 6 — Respond**
Follow the runbook: notify the owner, contain when warranted, protect the account, preserve logs, and document the decision.

### Case B — Unexpected account added to an administrator group

**Alert:** 4732 or 4728 indicates group membership changed.

1. Identify the group and new member.
2. Identify the subject who made the change.
3. Validate the change ticket and actor authorization.
4. Search for 4720/4722 if the account was just created or enabled.
5. Search for 4624, 4672, 4688, and relevant remote access records for the target account.
6. Determine whether the account performed unusual actions after membership changed.
7. Follow the approved containment path if unauthorized.

### Case C — New Windows service

**Alert:** 4697 Security or 7045 System.

1. Record service name, image path, start type, account, time, and host.
2. Confirm the software deployment or change ticket.
3. Review the executable's signature, hash, parent process, and storage path.
4. Correlate with process creation, downloads, and network activity.
5. Check whether the service started and what ran next.
6. Escalate if the binary is unexplained or evidence points to unwanted persistence.

### Case D — Security log cleared

**Alert:** 1102.

1. Treat as a priority investigation and preserve the available record.
2. Identify the account and host.
3. Validate with the administrator or maintenance owner.
4. Search central SIEM and other telemetry for the preceding and following activity.
5. Check for audit-policy, service, process, and privilege changes.
6. Document whether the event was authorized and what evidence remains.

### Case E — Suspicious process starts PowerShell

**Alert:** An unexpected parent launches PowerShell, or PowerShell logging captures an unusual script.

1. Review 4688/Sysmon 1 for parent, child, account, and command line.
2. Read 4103/4104 if available.
3. Look for file creation, DNS queries, or network connections from the process.
4. Review Defender detections and file signature/hash.
5. Determine if this matches an approved script or management job.
6. Preserve evidence and escalate if unexplained.

### Case F — Unusual domain service-ticket activity

**Alert:** A detection flags unusual 4769 behavior.

1. Identify the requesting account, client host, service account/SPN, time, and result.
2. Compare volume and target services with normal activity.
3. Inspect ticket encryption fields when available.
4. Check whether the source is an approved scanner, application server, or admin system.
5. Correlate with endpoint activity and other domain events.
6. Follow the organization's credential-exposure response if corroborating evidence exists.

---

## 16. SIEM Queries: Splunk SPL

The queries below are **templates**. Field names depend on your Splunk add-ons, sourcetype, and field extractions. Confirm them in your own data before using these searches as detections.

### 16.1 Failed logons by account and source

```spl
index=wineventlog EventCode=4625
| stats count AS failed_attempts
        earliest(_time) AS first_seen
        latest(_time) AS last_seen
  by host user src_ip Logon_Type
| sort - failed_attempts
```

**What it does:** Counts failed-logon records by host, user, source IP, and logon type. If your data uses `TargetUserName` or another field rather than `user`, adjust it.

### 16.2 Successful logons

```spl
index=wineventlog EventCode=4624
| stats count AS successful_logons
        earliest(_time) AS first_seen
        latest(_time) AS last_seen
  by host user src_ip Logon_Type
| sort - successful_logons
```

Review source IPs and logon types against the host's normal role.

### 16.3 Account creation

```spl
index=wineventlog EventCode=4720
| table _time host SubjectUserName TargetUserName Message
| sort - _time
```

### 16.4 Sensitive group membership changes

```spl
index=wineventlog (EventCode=4728 OR EventCode=4732 OR EventCode=4756)
| table _time host SubjectUserName TargetUserName GroupName EventCode Message
| sort - _time
```

Field names differ between data models and event providers. Validate the target user and group from the raw event if fields are missing.

### 16.5 Process creation

```spl
index=wineventlog EventCode=4688
| table _time host SubjectUserName NewProcessName CreatorProcessName Process_Command_Line
| sort - _time
```

Use the field name actually extracted by your Windows event input. Command-line content is not guaranteed to exist.

### 16.6 Log clear and audit policy change

```spl
index=wineventlog (EventCode=1102 OR EventCode=4719)
| table _time host user EventCode Message
| sort - _time
```

### 16.7 Service installation

```spl
(index=wineventlog EventCode=4697) OR (index=windows_system EventCode=7045)
| table _time host EventCode Message
| sort - _time
```

Adapt index names to your environment. Security and System events may be stored in the same or different indexes.

### 16.8 Basic investigation timeline

```spl
index=wineventlog host="YOUR-HOSTNAME"
    (EventCode=4624 OR EventCode=4625 OR EventCode=4672 OR EventCode=4688 OR EventCode=4697 OR EventCode=1102)
| table _time EventCode user src_ip Logon_Type NewProcessName Message
| sort _time
```

Replace the host with a known lab host. Expand the event list only when the question being investigated requires it.

---

## 17. SIEM Queries: Microsoft Sentinel KQL

Microsoft Sentinel table and field names depend on the connector. In the Windows Security Events via AMA connector, the `SecurityEvent` table is commonly used for Windows Security events. Other connectors may send data to different tables, such as `WindowsEvent`. Confirm the table schema first.

### 17.1 Recent failed logons

```kql
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4625
| project TimeGenerated, Computer, TargetAccount,
          IpAddress, LogonType, Activity, Status, SubStatus
| order by TimeGenerated desc
```

If a column does not exist in your connector, remove it or replace it with the actual column shown in the table schema.

### 17.2 Failed logons grouped by source and account

```kql
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4625
| summarize FailedAttempts=count(),
            FirstSeen=min(TimeGenerated),
            LastSeen=max(TimeGenerated)
    by Computer, TargetAccount, IpAddress
| order by FailedAttempts desc
```

This is a starting point for triage. It does not independently identify an attacker.

### 17.3 Successful sign-ins

```kql
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4624
| project TimeGenerated, Computer, TargetAccount, IpAddress, LogonType
| order by TimeGenerated desc
```

### 17.4 New accounts

```kql
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4720
| project TimeGenerated, Computer, SubjectAccount, TargetAccount, Activity
| order by TimeGenerated desc
```

### 17.5 Group membership changes

```kql
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID in (4728, 4729, 4732, 4733, 4756, 4757)
| project TimeGenerated, Computer, EventID, SubjectAccount,
          TargetAccount, Activity
| order by TimeGenerated desc
```

Check the event message or extracted fields to identify the exact group and member.

### 17.6 Audit log clearing and audit policy changes

```kql
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID in (1102, 4719)
| project TimeGenerated, Computer, EventID, SubjectAccount, Activity
| order by TimeGenerated desc
```

### 17.7 Process creation events

```kql
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4688
| project TimeGenerated, Computer, SubjectAccount,
          NewProcessName, Process, CommandLine, Activity
| order by TimeGenerated desc
```

The available process and command-line columns differ by schema. Validate your table before relying on this query.

### 17.8 Investigation time window

Use a narrow time window first, then expand it. For example, a suspicious sign-in may require reviewing activity 15 minutes before and after the event, but the right window depends on the alert and environment. Do not treat an example time window as a universal rule.

---

## 18. SOC Triage Checklist

Use this checklist when a Windows event triggers an alert.

### First look
- [ ] What is the alert name and triggering event?
- [ ] Which host and user are involved?
- [ ] What is the exact event time and time zone?
- [ ] Is the event enabled and expected in this environment?
- [ ] Is the asset a workstation, server, or domain controller?

### Context
- [ ] What happened just before the event?
- [ ] What happened just after it?
- [ ] Is there a matching successful/failed logon?
- [ ] Is there process, PowerShell, Sysmon, Defender, DNS, or network evidence?
- [ ] Is the account privileged or sensitive?
- [ ] Is the behavior new compared with the normal baseline?

### Decision and action
- [ ] Is there an approved change, scheduled task, or administrator activity?
- [ ] What evidence supports a benign or suspicious conclusion?
- [ ] Is the severity based on impact and evidence, not just event count?
- [ ] Does the response require account protection, endpoint isolation, or escalation?
- [ ] Have relevant records been preserved?
- [ ] Is the case report clear enough for another analyst to continue?

### Simple case report template

```text
Case ID:
Alert title:
Severity:
Host:
User/account:
Start and end time (include time zone):
Event IDs:
Source and destination details:
What happened:
Evidence collected:
Related events:
Business context checked:
Assessment (benign / suspicious / confirmed, with reason):
Actions taken:
Next owner / next step:
```

Do not label a case "confirmed compromise" unless the evidence supports that conclusion.

---

## 19. Common Mistakes

1. **Treating one event as proof.** An Event ID is a lead. Correlate records and context.
2. **Ignoring audit configuration.** Some data is missing unless the right policy is enabled.
3. **Confusing account fields.** The subject, target, and process account can be different.
4. **Reading only the event number.** Review the full message and important details.
5. **Mixing Windows Security and Sysmon IDs.** They are different providers with different meanings.
6. **Assuming all logon type 3 events are remote attacks.** Network logons occur during normal services too.
7. **Using a hard-coded threshold everywhere.** The right threshold depends on account types, host role, normal traffic, and time window.
8. **Ignoring the host's role.** A domain controller and a developer workstation have different normal behaviors.
9. **Ignoring time zones and ingestion delay.** Incorrect ordering can create a false story.
10. **Making changes before preserving evidence.** Follow the organization's approved response and evidence-handling process.
11. **Copying queries without checking field names.** SIEM schemas and connectors vary.
12. **Sharing real logs publicly.** Scrub user names, addresses, domains, device IDs, tokens, and sensitive organization details.

---

## 20. Practice Tasks

Complete these in your own lab and document screenshots and findings.

### Beginner
1. Open Event Viewer and locate a successful logon event (4624), if available.
2. Locate failed logon events (4625), if available.
3. Explain three fields in the event's Details view.
4. Find an event from the System log and explain how it differs from a Security event.
5. Run the PowerShell query in Section 3 and save the output without sensitive details.

### Intermediate
6. Group 4625 records by source address and target account in a SIEM.
7. Investigate an account-creation event (4720) and search for related group changes.
8. Find process-creation records (4688) and explain the parent and child process.
9. Create a timeline that combines logon, privilege, process, and service events.
10. Write a short incident report using the template in Section 18.

### Advanced
11. Review 4769 events on a lab domain controller and compare them with a normal baseline.
12. Compare Security 4688 with Sysmon Event 1 for the same process.
13. Create a detection for unusual group membership changes and document known false positives.
14. Test whether clearing an event log is visible in the central SIEM, using an isolated lab only and following approved procedures.
15. Build a rule, test it against benign and suspicious examples, and record precision limitations.

For every task, include: **objective → setup → steps → evidence → result → interpretation → limitations → recommended response**.

---

## 21. Quick Reference Tables

### Most useful starting points

| Goal | Start with |
|---|---|
| Review user logons | 4624, 4625, 4634, 4647 |
| Investigate alternate credentials | 4648 |
| Check privileged logons | 4672 |
| Find account changes | 4720, 4722, 4724, 4725, 4726, 4738 |
| Find group changes | 4728, 4729, 4732, 4733, 4756, 4757 |
| Investigate lockouts | 4740, plus 4625 |
| Review process starts | 4688 or Sysmon 1 |
| Review PowerShell scripts | PowerShell 4103 / 4104 when enabled |
| Investigate services | Security 4697, System 7045 |
| Investigate security log clearing | 1102 |
| Investigate audit policy changes | 4719 |
| Investigate file share access | 5140, 5145 |
| Investigate object access | 4663, with appropriate auditing |
| Investigate Kerberos | 4768, 4769, 4771 |
| Review directory object changes | 5136, with appropriate auditing |
| Add process-to-network context | Sysmon 1, 3, and 22 where configured |

### Event severity is not the same as Event ID

Windows Event IDs do not have one universal SOC severity. A detection rule assigns its severity based on context, risk, confidence, asset criticality, and corroborating evidence. Event 1102 may receive high priority because clearing a security log can reduce visibility, but the analyst still needs to investigate authorization and circumstances.

---

## 22. Glossary

- **Authentication:** Checking that an identity is genuine.
- **Authorization:** Deciding what an identity is allowed to do.
- **Audit policy:** Configuration that controls which activities Windows records.
- **Baseline:** A description of normal activity for a user, host, or network.
- **Correlation:** Linking different events to understand one activity.
- **Domain Controller (DC):** A server that provides identity and directory services for an Active Directory domain.
- **False positive:** An alert that looks suspicious but is actually legitimate.
- **IOC:** Indicator of Compromise, such as a known malicious file hash or domain.
- **Lateral movement:** Moving from one host or account to another after initial access.
- **Logon ID:** An identifier that helps connect events within a logon session on a host.
- **Persistence:** A way an unwanted program or actor tries to keep access.
- **SIEM:** Security Information and Event Management system used to collect and analyze security telemetry.
- **Triage:** The first review used to decide urgency and next steps.
- **TGT:** Kerberos Ticket Granting Ticket used as part of domain authentication.
- **SPN:** Service Principal Name that identifies a service account/service in Kerberos.
- **Sysmon:** Microsoft Sysinternals tool that adds detailed system activity telemetry when configured.
- **KQL:** Kusto Query Language, used by Microsoft Sentinel and other Microsoft data services.
- **SPL:** Search Processing Language used by Splunk.

---

## 23. Official References

Use official documentation to validate event definitions, configuration requirements, and differences between Windows versions:

- [Microsoft: Audit logon events](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-logon)
- [Microsoft: Advanced security audit policy settings](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-audit-policy-settings)
- [Microsoft: Windows Security auditing overview](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/basic-audit-logon-events)
- [Microsoft: Event Viewer](https://learn.microsoft.com/en-us/shows/inside/event-viewer)
- [Microsoft Sysinternals: Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Microsoft Sentinel: SecurityEvent table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/securityevent)
- [Microsoft Sentinel: Kusto Query Language](https://learn.microsoft.com/en-us/kusto/query/)
- [Splunk: Search Reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/)

---

## Final Note

Learning Event IDs means learning how to ask better questions about system activity. Memorizing numbers is useful, but the most important SOC skill is connecting evidence, validating context, documenting a clear conclusion, and choosing a response that matches the risk.

**Learn → Collect → Correlate → Investigate → Document → Respond**

This guide is for defensive cybersecurity education and authorized lab practice. Always follow your organization's policies and applicable laws.
