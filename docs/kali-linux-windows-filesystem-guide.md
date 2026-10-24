# Kali Linux and Windows File Systems — Complete Beginner's Guide
### Simple English • Side-by-Side Comparison • Practical Commands • SOC Use

> This original guide explains how Kali Linux and Windows organize files, important folders, paths, permissions, storage, commands, and forensic clues. Practice only on systems and files you are authorized to inspect.

## Table of Contents
1. What is a file system?
2. Linux vs Windows at a glance
3. Kali Linux directory tree
4. Important Linux directories
5. Windows directory tree
6. Important Windows directories
7. Path syntax and examples
8. File types and extensions
9. Linux permissions
10. Windows NTFS permissions
11. Useful Linux commands
12. Useful Windows commands
13. Disks, partitions, and mounts
14. Logs, configuration, and temporary files
15. Hidden files and protected locations
16. File-system investigation for SOC analysts
17. Side-by-side path map
18. Safe practice labs
19. Interview questions
20. Glossary and official references

---

## 1. What is a file system?

A **file system** is the method an operating system uses to store, name, organize, find, and protect data on a storage device.

Imagine a library:
- A **disk** is the whole library building.
- A **partition** is one section of the building.
- A **folder/directory** is a room or shelf.
- A **file** is a book or document.
- **Permissions** are the rules about who can read or change the book.
- **Metadata** is information about a file, such as its size, owner, timestamps, and attributes.

A file system is not the same thing as a directory tree. The file system is the storage format and rules (for example, ext4 or NTFS). The directory tree is the arrangement of folders and files users see.

### Important terms
- **Disk:** Physical or virtual storage device.
- **Partition:** A defined region of a disk.
- **Volume:** A storage area made available to an operating system.
- **Mount point:** A Linux directory where another file system is attached.
- **Drive letter:** A Windows access name such as C: or D:.
- **Absolute path:** A full path starting from a root or volume root.
- **Relative path:** A path described from the current directory.

## 2. Linux vs Windows at a glance

| Topic | Kali Linux | Windows |
|---|---|---|
| Common file systems | ext4 is common; others are possible | NTFS is common for system volumes; FAT32/exFAT often appear on removable media |
| Root layout | One main tree beginning at / | Volumes commonly have roots such as C:\ and D:\ |
| Path separator | Forward slash / | Backslash \\ in displayed paths |
| User home | /home/username | C:\Users\username |
| System configuration | Many files under /etc | Registry and Windows/application configuration folders |
| Programs | Often under /usr, /opt, /usr/local and package-managed locations | Often under C:\Program Files and C:\Program Files (x86) |
| Shared application data | Depends on application; may be under /var/lib or /usr/share | Often C:\ProgramData |
| User application settings | Often ~/.config and hidden home files | Often %APPDATA% and %LOCALAPPDATA% |
| Temporary files | Commonly /tmp and /var/tmp | Commonly %TEMP% and C:\Windows\Temp |
| Logs | Commonly /var/log and systemd journal | Event Viewer plus application-specific logs |
| Permissions | Owner/group/other mode bits; ACLs are also possible | NTFS ACLs, groups, and inherited permissions |
| Case sensitivity | Usually case-sensitive | Usually case-insensitive but case-preserving on normal Windows volumes; exceptions exist |
| Executables | Execute permission, file content, and interpreter matter; extension not required | Common types include .exe, .com, .bat, .cmd; scripts depend on their handler |
| Removable storage | Mounted under a directory, often /media or /mnt | Often assigned a drive letter or mounted path |

These are common patterns, not absolute rules. A computer may use custom paths, additional drives, encryption, network shares, or different configurations.

---

## 3. Kali Linux directory tree

Linux has one main directory tree. Its top is the root directory, written as a single forward slash: /

~~~text
/
├── bin       Essential commands (often linked into /usr/bin)
├── boot      Kernel and boot-related files
├── dev       Device interfaces
├── etc       System-wide configuration
├── home      Normal users' personal folders
│   └── student
│       ├── Desktop
│       ├── Documents
│       ├── Downloads
│       ├── Pictures
│       └── .config
├── lib       Essential libraries (may link into /usr/lib)
├── media     Common mount location for removable devices
├── mnt       Manual or temporary mount points
├── opt       Some optional/third-party software
├── proc      Virtual process and kernel information
├── root      Root administrator's home directory
├── run       Runtime state since boot
├── sbin      System administration commands (often linked into /usr/sbin)
├── srv       Data served by services, when used
├── sys       Virtual kernel/device information
├── tmp       Temporary files
├── usr       Most user-space programs, libraries, documentation
└── var       Changing data: logs, caches, application state
~~~

This is a simplified tree based on common Linux conventions. A real system can contain more folders, symbolic links, and mounted file systems.

**Three key facts**
1. / is the top of the whole Linux tree.
2. /root is the root administrator's home, not the root directory.
3. /home/student is only an example; your username may differ.

## 4. Important Linux directories

### / — Root directory
Every absolute Linux path starts from /. Examples include /etc/hosts and /home/student/Downloads.

### /home — Normal users' personal data
Example: /home/student. It may contain documents, downloads, scripts, SSH client settings, shell settings, and application preferences. SOC investigations may review user folders for downloaded files or scripts, subject to permissions and evidence-handling rules.

### /root — Root user's home
The root account's personal home directory is normally /root. It often has restricted access. Do not confuse the directory with the root user itself.

### /etc — System-wide configuration
Common examples:
- /etc/hostname — hostname setting on many Linux systems.
- /etc/hosts — local hostname/address mappings.
- /etc/passwd — account information; not normal plaintext passwords.
- /etc/shadow — password hashes and aging information; restricted.
- /etc/fstab — file systems configured for mounting.
- /etc/ssh/ — SSH configuration files, depending on installed components.
- /etc/sudoers and /etc/sudoers.d/ — delegated administrative command rules.

Editing configuration without a backup or validation can break services or system access.

### /usr — Programs and shared resources
- /usr/bin — many commands and programs.
- /usr/sbin — many administration programs.
- /usr/lib — libraries and support files.
- /usr/share — documentation and architecture-independent resources.
- /usr/local — software installed locally outside the normal distribution-managed locations.

On modern Linux systems, /bin, /sbin, and /lib may be symbolic links into /usr.

### /var — Data that changes
- /var/log — logs.
- /var/cache — cached data.
- /var/tmp — temporary data that may persist longer than /tmp.
- /var/lib — application/service state.
- /var/spool — queued work for services, where used.
- /var/www — common web content location, but not guaranteed.

Logs can be rotated, restricted, or stored elsewhere. Do not assume every log exists.

### /tmp — Temporary files
Programs may place short-lived files here. Cleanup rules vary. A file in /tmp is not automatically malicious. Preserve potential evidence before deleting it.

### /dev — Device interfaces
Examples may include /dev/null, /dev/zero, /dev/pts/, and disk device nodes. Device names vary; never assume the main disk is always /dev/sda.

### /proc — Virtual process/kernel information
This is a virtual file system, not a normal collection of stored documents. Examples: /proc/cpuinfo, /proc/meminfo, /proc/mounts, and /proc/PID/ for process details.

### /sys — Kernel and device information
Exposes information about devices, drivers, and kernel objects. It is not a normal place for personal documents.

### /boot — Boot files
May contain the kernel, initramfs images, and bootloader-related files. Incorrect changes can prevent booting.

### /lib and /lib64 — Essential libraries
These may hold shared libraries and kernel modules, or link into /usr on modern distributions.

### /media and /mnt — Mount points
/media is commonly used for automatically mounted removable media; /mnt is commonly used for manual mounts. Both are conventions, not strict requirements.

### /opt — Optional software
Some third-party applications may be installed here. Many tools live elsewhere.

### /run — Runtime state
Contains temporary runtime information such as sockets and process/service state; it is usually cleared on reboot.

### /srv — Service data
May contain data served by services. Many systems do not use it.

### /lost+found — Recovered file fragments
May exist on ext-family file systems. File-system repair tools can place recovered items there.

---

## 5. Windows directory tree

Windows commonly exposes storage volumes through drive letters. C: is often the system volume, but not always.

~~~text
C:\
├── $Recycle.Bin           Recycle Bin data for this volume
├── Program Files\         Common location for 64-bit applications
├── Program Files (x86)\   Common location for 32-bit apps on 64-bit Windows
├── ProgramData\           Shared application data
├── Users\
│   ├── Public\            Shared public user files
│   └── Student\
│       ├── Desktop\
│       ├── Documents\
│       ├── Downloads\
│       ├── Pictures\
│       ├── AppData\
│       │   ├── Local\
│       │   ├── LocalLow\
│       │   └── Roaming\
│       └── NTUSER.DAT      User Registry hive file
├── Windows\               Core operating-system files
│   ├── System32\          Important system tools and components
│   ├── SysWOW64\          32-bit components on 64-bit Windows
│   ├── Temp\              Windows temporary files
│   ├── Logs\              Some component logs
│   └── WinSxS\            Windows component store
├── pagefile.sys            Paging file, if configured
└── hiberfil.sys            Hibernation-related file, if enabled
~~~

This is an example, not a complete tree. Windows can have recovery and EFI partitions, additional volumes, OneDrive folders, custom application paths, and organization-managed folders.

## 6. Important Windows directories

### C:\ — Root of the C: volume
This is the root of one volume, not necessarily the whole computer. Other volumes may use D:, E:, or directory mount points.

### C:\Windows\ — Operating system
Contains Windows components, services, tools, libraries, resources, and system-managed files. Do not manually delete files from this folder.

### C:\Windows\System32\
Contains many important Windows binaries, libraries, and tools. On 64-bit Windows, this folder commonly contains 64-bit system components.

### C:\Windows\SysWOW64\
On 64-bit Windows, this commonly contains 32-bit components for compatibility. The names can feel backwards:
- System32 commonly contains 64-bit components on 64-bit Windows.
- SysWOW64 commonly contains 32-bit components.

This is a historical naming convention.

### C:\Program Files\
Common location for 64-bit desktop applications on 64-bit Windows. Applications can use custom locations.

### C:\Program Files (x86)\
Common location for 32-bit desktop applications on 64-bit Windows. It may not exist on 32-bit Windows.

### C:\ProgramData\
Stores shared application data not tied to one user. It may be hidden by default. Its exact contents depend on installed software.

### C:\Users\
Contains profile folders. A user profile may contain Desktop, Documents, Downloads, Pictures, Videos, AppData, and user-specific settings.

### AppData\Local, AppData\LocalLow, and AppData\Roaming
Usually under a user profile:
- **Local:** Local application data and caches.
- **LocalLow:** Data for certain lower-integrity application contexts.
- **Roaming:** Settings that may roam in supported profile setups; not every organization uses roaming profiles.

Use environment variables instead of guessing exact profile paths: %APPDATA%, %LOCALAPPDATA%, and %USERPROFILE%.

### C:\Users\Public\
A shared profile location intended for public user files. Actual access depends on permissions.

### $Recycle.Bin
Stores Recycle Bin data for a volume. Not every deleted file remains there; deletion method and settings matter.

### System Volume Information
A protected folder used for system-managed volume information. Depending on configuration it may include restore-point or shadow-copy-related data. Do not change it manually.

### pagefile.sys
A paging file used as part of virtual-memory management. It is not a normal user document.

### hiberfil.sys
Used for hibernation and related power features when enabled.

### Temporary folders
Common locations include C:\Windows\Temp and the path in %TEMP%. Temporary folders can contain legitimate caches, installer files, and possibly useful investigation artifacts. A file's presence there is not proof of malware.

### C:\Windows\WinSxS\
The Windows component store. Do not manually delete files from it to free space; use supported Windows cleanup tools.

### Event Viewer and log files
Many system/security events are managed by the Windows Event Log service and viewed in Event Viewer, rather than as ordinary text files. A common on-disk location for EVTX files is C:\Windows\System32\winevt\Logs\, but access is restricted and log configuration varies.

### Registry hive files
Windows stores Registry data in system-managed hive files. A user profile commonly includes NTUSER.DAT. The Registry is a configuration database, not just another folder. Do not edit hive files directly as a beginner.

---

## 7. Path syntax and examples

| Meaning | Kali Linux | Windows |
|---|---|---|
| Root | / | C:\ (one volume root) |
| User home | /home/student | C:\Users\Student |
| Desktop | /home/student/Desktop | C:\Users\Student\Desktop |
| Downloads | /home/student/Downloads | C:\Users\Student\Downloads |
| System configuration | /etc and app-specific paths | Registry and Windows/application configuration paths |
| Common commands | /usr/bin and /usr/sbin | C:\Windows\System32 and other locations |
| Temporary files | /tmp and /var/tmp | %TEMP% and C:\Windows\Temp |
| Logs | /var/log and system journal | Event Viewer and component-specific logs |
| Removable media | Mount point under /media or /mnt | Drive letter or mount point |

These are conceptual comparisons, not exact equivalents. Windows Registry settings do not all map to one Linux folder.

### Absolute vs relative paths

Linux absolute path:
~~~bash
/home/student/Documents/notes.txt
~~~

Windows absolute path:
~~~text
C:\Users\Student\Documents\notes.txt
~~~

If your current directory is /home/student, then Documents/notes.txt is a relative path to the same file. In PowerShell, if your current directory is C:\Users\Student, Documents\notes.txt is a relative path.

Useful symbols:
- . means current directory in common shell contexts.
- .. means parent directory.
- ~ usually means the current user's home in Linux shells and PowerShell.
- Linux uses / as its normal path separator.
- Windows paths are commonly displayed with backslashes.

### Navigation examples

Linux:
~~~bash
pwd
cd /home/student
cd Documents
cd ..
cd ~
~~~

PowerShell:
~~~powershell
Get-Location
Set-Location $HOME
Set-Location Documents
Set-Location ..
~~~

---

## 8. File types and extensions

### Linux file types
- **Regular file:** Text, code, image, archive, or binary content.
- **Directory:** Organizes names and paths.
- **Symbolic link:** A reference to another path.
- **Character device:** Device interface that handles data as a stream.
- **Block device:** Device interface that transfers data in blocks.
- **Socket:** Communication endpoint.
- **FIFO/named pipe:** Inter-process communication object.

Useful inspection commands:
~~~bash
file sample
ls -l sample
stat sample
readlink -f sample
~~~

Linux does not require an extension to execute a program. Content, executable permission, interpreter, and how the file is launched all matter.

Common extensions:
- .sh — often shell scripts.
- .py — often Python scripts.
- .conf — often configuration.
- .log — often log files.
- .deb — Debian package.
- .tar.gz — gzip-compressed tar archive.

### Windows file types

| Extension | Common meaning | Security note |
|---|---|---|
| .exe | Executable program | Check source, signature, and behavior |
| .dll | Dynamic-link library | Usually loaded by programs |
| .sys | System driver | Drivers can run with high privilege |
| .bat / .cmd | Command scripts | Contain commands for Command Prompt |
| .ps1 | PowerShell script | Behavior depends on its content and execution context |
| .msi | Windows Installer package | Can install or change software |
| .lnk | Shortcut | Points to a target and may include arguments |
| .evtx | Windows Event Log file | Contains structured event records |
| .reg | Registry import/export format | Can change Registry values when imported |
| .zip | Archive | May contain many file types |
| .iso | Disk image | Often used for install media |
| .docx | Word document | May contain embedded content or links |

An extension is a naming convention, not proof of file contents or safety. In File Explorer, use View → Show → File name extensions where that option is available.

---

## 9. Linux permissions

Linux's basic permission model describes three classes:
- **User/owner (u):** The file owner.
- **Group (g):** Members of the file's group.
- **Other (o):** Everyone else, subject to other controls.

Basic permissions:
- **r — Read:** Read file content; for a directory, list names when other required permissions are available.
- **w — Write:** Change file content; for a directory, change entries when the other required permissions are available.
- **x — Execute:** Run an executable file when allowed; for a directory, traverse/search it.

Example:
~~~text
-rwxr-xr--
~~~
- First character - means regular file.
- rwx: owner can read, write, execute.
- r-x: group can read and execute.
- r--: others can read.

Directories often begin with d, for example drwxr-xr-x.

### Numeric permissions

| Number | Permission |
|---:|---|
| 0 | None |
| 1 | Execute |
| 2 | Write |
| 3 | Write + execute |
| 4 | Read |
| 5 | Read + execute |
| 6 | Read + write |
| 7 | Read + write + execute |

For chmod 750:
- Owner: 7 = rwx.
- Group: 5 = r-x.
- Other: 0 = no access.

Examples:
~~~bash
ls -l file.txt
id
whoami
chmod 640 file.txt
chmod u+x script.sh
stat file.txt
~~~

Changing ownership:
~~~bash
sudo chown student:student file.txt
~~~

Use chown only when you understand the intended owner and group. Avoid chmod -R 777 as a generic fix; it can grant broad access recursively.

### Directory permission nuance
For a directory, read lets you list names, execute lets you traverse/search, and write lets you change entries when other requirements are satisfied. A file can still be inaccessible if a parent directory blocks traversal.

### Special permission bits
- **setuid:** In certain cases, a program runs with the file owner's effective user ID.
- **setgid:** Can affect a program's group ID or new-file group inheritance on a directory.
- **sticky bit:** On a shared writable directory, limits who can delete or rename entries.

These have legitimate uses and need context; a special bit alone does not prove malicious behavior.

---

## 10. Windows NTFS permissions

Windows commonly uses **Access Control Lists (ACLs)** to define access. An ACL contains entries granting or denying rights to users and groups.

Important terms:
- **Security principal:** A user, group, or service identity.
- **DACL:** Discretionary Access Control List; controls access allowed or denied.
- **ACE:** One access rule in an ACL.
- **Inheritance:** Child files/folders can inherit permissions from a parent.
- **Owner:** Identity that owns an object.
- **UAC:** User Account Control, which helps manage when administrative rights are used.

Common rights:
- **Read:** View file data or list a folder, depending on the object.
- **Write:** Change data or create items, depending on rights.
- **Modify:** Usually read, write, execute, and delete.
- **Read & execute:** Read data and execute where applicable.
- **Full control:** Broad rights, commonly including changing permissions and ownership.
- **Deny:** Explicitly denies selected rights; its effect depends on the full access-check context.

### View permissions in File Explorer
1. Right-click a file/folder and select Properties.
2. Open Security.
3. Select a user/group.
4. Review allowed permissions.
5. Use Advanced to inspect inheritance and detailed rules.

### View permissions with commands

Command Prompt:
~~~cmd
whoami
icacls "%USERPROFILE%\Documents"
icacls "C:\Program Files"
~~~

PowerShell:
~~~powershell
Get-Acl "$HOME\Documents" | Format-List
Get-ChildItem "$HOME\Documents" -Force
~~~

icacls displays/manages ACLs. Get-Acl returns access-control information. The -Force listing option can show hidden items; it does not bypass access controls.

### Inheritance example
A parent folder may grant read access to a group. Child files can inherit it. A child can also have explicit permissions or inheritance disabled. Always inspect the actual ACL rather than guessing from a folder name.

### Linux vs Windows permissions

| Question | Linux mode bits | Windows NTFS ACLs |
|---|---|---|
| Who can access? | Owner, group, other; ACLs can extend this | Users/groups in ACL entries |
| Rights | Basic read/write/execute | Detailed rights such as modify, delete, change permissions |
| Inheritance | Basic mode bits do not behave like NTFS inheritance; default ACLs can affect new objects | Commonly inherited from parent folders |
| Inspect | ls -l, stat, getfacl | Security tab, icacls, Get-Acl |
| Change | chmod, chown, setfacl | icacls or supported security interfaces |

---

## 11. Useful Linux commands

Run these in a Kali terminal. Most examples are read-only, but commands that create or remove files should be used only in your own practice folder.

### Navigation
~~~bash
pwd
ls
ls -la
cd /etc
cd ..
cd ~
~~~

### Create and inspect a safe test file
~~~bash
mkdir -p ~/fs-lab/docs
touch ~/fs-lab/docs/notes.txt
printf 'Linux file system practice\n' > ~/fs-lab/docs/notes.txt
cat ~/fs-lab/docs/notes.txt
file ~/fs-lab/docs/notes.txt
stat ~/fs-lab/docs/notes.txt
~~~

### Copy, move, remove
~~~bash
cp notes.txt notes-backup.txt
mv notes-backup.txt archive.txt
mkdir archive
mv archive.txt archive/
rm archive/archive.txt
~~~
Run these only with correct test paths. rm normally deletes rather than moving to a graphical Recycle Bin.

### Search
~~~bash
find ~/fs-lab -type f
find ~/fs-lab -type f -name '*.txt'
grep -Rni 'practice' ~/fs-lab
command -v python3
~~~

### Storage and mounts
~~~bash
df -h
du -sh ~/fs-lab
lsblk -f
findmnt
~~~
- df -h: space usage on mounted file systems.
- du -sh: estimated size of a directory.
- lsblk -f: block devices and file-system information.
- findmnt: mounted file systems.

### Process and file use
~~~bash
ps aux
lsof ~/fs-lab/docs/notes.txt
~~~
lsof may need installation or additional permissions.

**Danger:** Do not experiment casually with rm -rf, mkfs, dd writing to a device, or partitioning commands. A wrong path or disk can destroy data.

---

## 12. Useful Windows commands

Use PowerShell or Command Prompt. They are different shells, so syntax differs.

### Navigation and listing

PowerShell:
~~~powershell
Get-Location
Set-Location $HOME
Get-ChildItem
Get-ChildItem -Force
Get-ChildItem C:\Windows -Directory
~~~

Command Prompt:
~~~cmd
cd
cd %USERPROFILE%
dir
dir /a
cd ..
~~~

### Create and inspect a safe test file

PowerShell:
~~~powershell
New-Item -ItemType Directory -Path "$HOME\fs-lab\docs" -Force
Set-Content "$HOME\fs-lab\docs\notes.txt" "Windows file system practice"
Get-Content "$HOME\fs-lab\docs\notes.txt"
Get-Item "$HOME\fs-lab\docs\notes.txt" | Format-List *
~~~

Command Prompt:
~~~cmd
mkdir "%USERPROFILE%\fs-lab\docs"
echo Windows file system practice > "%USERPROFILE%\fs-lab\docs\notes.txt"
type "%USERPROFILE%\fs-lab\docs\notes.txt"
~~~

### Copy, rename, move, remove

PowerShell:
~~~powershell
Copy-Item "$HOME\fs-lab\docs\notes.txt" "$HOME\fs-lab\docs\notes-copy.txt"
Rename-Item "$HOME\fs-lab\docs\notes-copy.txt" "archive.txt"
New-Item -ItemType Directory "$HOME\fs-lab\archive" -Force
Move-Item "$HOME\fs-lab\docs\archive.txt" "$HOME\fs-lab\archive\"
Remove-Item "$HOME\fs-lab\archive\archive.txt"
~~~

Check each path before Remove-Item. Recursive deletion can remove many files.

### Search
~~~powershell
Get-ChildItem "$HOME\fs-lab" -Recurse -File
Get-ChildItem "$HOME\fs-lab" -Recurse -Filter *.txt
Select-String -Path "$HOME\fs-lab\docs\notes.txt" -Pattern "practice"
Get-Command powershell
~~~

Command Prompt:
~~~cmd
where powershell
where python
findstr /i "practice" "%USERPROFILE%\fs-lab\docs\notes.txt"
~~~

### Storage
~~~powershell
Get-Volume
Get-PSDrive -PSProvider FileSystem
Get-ChildItem C:\ -Force
~~~

Command Prompt:
~~~cmd
fsutil volume diskfree C:
~~~
Some commands need administrator rights. Do not format or repartition a drive for a basic learning task.

---

## 13. Disks, partitions, and mounts

A simplified storage model:

~~~text
Physical or virtual disk
        ↓
Partition or volume layout
        ↓
File system (for example ext4 or NTFS)
        ↓
Mount point / drive letter
        ↓
Directories and files
~~~

Modern computers may add encryption, logical volume management, RAID, Storage Spaces, virtual disks, and other layers.

### Kali inspection
~~~bash
lsblk -f
df -h
findmnt
~~~
A **block device** stores/transfers data in blocks. A **partition** is a region of a disk. A **file system** organizes files. **Mounting** attaches a file system to a directory.

### Windows inspection
~~~powershell
Get-Disk
Get-Partition
Get-Volume
Get-PSDrive -PSProvider FileSystem
~~~
A **disk** is physical or virtual storage. A **partition** is a defined region. A **volume** is storage made available to Windows. A **drive letter** is a common access name. A volume can also be mounted into a directory.

Do not delete, format, or modify partitions unless you fully understand the target and the data is disposable.

---

## 14. Logs, configuration, and temporary files

### Common Linux locations

| Location | Typical contents | Possible investigation use |
|---|---|---|
| /var/log/ | System and service logs | Troubleshooting and timeline context |
| /etc/ | System configuration | Understand service/system settings |
| /tmp/ | Temporary files | Installer or application artifacts |
| /var/tmp/ | Temporary files that may persist longer | Additional artifact context |
| ~/.bash_history | Saved interactive Bash history, if enabled | May show commands but can be incomplete or edited |
| ~/.ssh/ | SSH configuration and keys, if present | Sensitive connection/identity material; protect it |
| /var/lib/ | Application/service state | Service-specific investigation |
| /run/ | Runtime state | Current service state and sockets |

Not all logs are enabled or stored as text. Some systems use the systemd journal. Access and retention vary.

### Common Windows locations

| Location | Typical contents | Possible investigation use |
|---|---|---|
| Event Viewer / Windows Event Logs | Structured system/security records | Logon, policy, service, application activity |
| %TEMP% | User temporary files | Installer/application artifacts |
| C:\Windows\Temp\ | System temporary files | Service or installer artifacts |
| %APPDATA% | User application data | Settings and app state |
| %LOCALAPPDATA% | Local user application data/caches | Local app artifacts |
| C:\ProgramData\ | Shared application data | System-wide application state |
| C:\Windows\Prefetch\ | Prefetch files when available/enabled | Possible timeline context; needs careful interpretation |
| C:\$Recycle.Bin\ | Recycle Bin data | Some deleted-file artifacts may remain |
| C:\Windows\System32\winevt\Logs\ | Common location for EVTX files | Structured event logs; access is restricted |

These are common locations, not guarantees. Configuration, retention, permissions, and software behavior affect what exists.

### Timestamps are clues, not proof
Files may have creation, modification, access, and metadata-change times, depending on the platform and file system. Copying, extracting, synchronizing, software behavior, or tampering can affect timestamps. Correlate them with other evidence.

---

## 15. Hidden files and protected locations

### Linux
A filename beginning with a dot is hidden from normal ls output:
- ~/.bashrc
- ~/.profile
- ~/.config/
- ~/.ssh/

Show hidden entries:
~~~bash
ls -la ~
~~~

Hidden does not mean encrypted or secure. Permissions control access.

### Windows
Windows uses Hidden and System attributes. File Explorer often hides some items by default.

Show hidden entries in PowerShell:
~~~powershell
Get-ChildItem "$HOME" -Force
Get-Item "$HOME\somefile" -Force | Select-Object FullName, Attributes
~~~

Hidden/system status is not a reliable malware indicator. Many legitimate operating-system files use these attributes.

### Least privilege
Use a normal account for daily work when possible. Elevate only when required and approved. Do not make system folders broadly writable to get around permission problems.

---

## 16. File-system investigation for SOC analysts

A SOC analyst may need to understand where a file came from, whether it is expected, which user or process touched it, and whether other telemetry supports suspicious activity.

### Repeatable investigation workflow
1. **Define the question.** Example: Why did an unfamiliar executable appear in a user's Downloads folder?
2. **Record scope.** Host, user, path, time range, alert, and relevant asset details.
3. **Preserve evidence.** Follow your organization's process. Do not run or delete the file.
4. **Inspect metadata.** Record size, timestamps, owner/permissions, file type, and hash.
5. **Check provenance.** Was it downloaded, installed by approved software, extracted, or created by a script?
6. **Correlate telemetry.** Review process creation, authentication, PowerShell, Sysmon, Defender, network, and file-access events where available.
7. **Compare with a baseline.** Is this normal for the host and user?
8. **Assess impact.** Is there evidence of execution, persistence, credential access, sensitive file access, or network communication?
9. **Respond by policy.** Escalate or contain through approved procedures.
10. **Document the conclusion.** State what is known, unknown, and supported by evidence.

### Kali: inspect without executing
~~~bash
file suspicious_sample
stat suspicious_sample
sha256sum suspicious_sample
ls -l suspicious_sample
~~~
A hash identifies exact bytes for comparison; it does not say whether a file is malicious.

### Windows: inspect without executing
~~~powershell
Get-Item "C:\path\to\sample" -Force |
  Select-Object FullName, Length, CreationTime, LastWriteTime, Attributes

Get-FileHash "C:\path\to\sample" -Algorithm SHA256
Get-AuthenticodeSignature "C:\path\to\sample"
~~~
A valid signature is useful evidence, not a guarantee of safety. An unsigned file is not automatically malicious.

### Evidence may be missing
- Audit logging may not have been enabled.
- Logs may have rolled over or been cleared.
- The endpoint may have been offline.
- A file may have been copied from another volume.
- Timestamps may not show the original download/creation time.
- SIEM ingestion time may differ from event time.

Record limitations instead of guessing.

---

## 17. Side-by-side path map

| Task | Kali Linux | Windows |
|---|---|---|
| Find user home | /home/username | C:\Users\username |
| Find downloads | ~/Downloads | %USERPROFILE%\Downloads |
| Find desktop | ~/Desktop | %USERPROFILE%\Desktop |
| System configuration | /etc and application paths | Registry, C:\Windows, app-specific locations |
| Common system commands | /usr/bin, /usr/sbin | C:\Windows\System32 and other locations |
| User app settings | ~/.config and hidden home files | %APPDATA%, %LOCALAPPDATA% |
| Temporary files | /tmp, /var/tmp | %TEMP%, C:\Windows\Temp |
| System logs | /var/log, system journal | Event Viewer and component log files |
| Permissions | ls -l, stat, getfacl | Security tab, icacls, Get-Acl |
| File hash | sha256sum file | Get-FileHash file -Algorithm SHA256 |
| Search files | find | Get-ChildItem -Recurse |
| Inspect storage | lsblk -f, df -h, findmnt | Get-Disk, Get-Partition, Get-Volume |

These are conceptual comparisons. There is no exact one-to-one folder equivalent for every operating-system component.

---

## 18. Safe practice labs

Use a disposable VM or a dedicated test folder. Do not alter protected system files.

### Lab A — Kali Linux

**Task 1: Identify your current user and location**
~~~bash
pwd
whoami
id
~~~
Write down your current directory and username.

**Task 2: Explore top-level folders**
~~~bash
ls /
ls -ld /etc /home /tmp /usr /var /root
~~~
Write one sentence about each directory.

**Task 3: Create and inspect a harmless file**
~~~bash
mkdir -p ~/fs-lab/docs
printf 'Linux file system practice\n' > ~/fs-lab/docs/notes.txt
ls -la ~/fs-lab
stat ~/fs-lab/docs/notes.txt
file ~/fs-lab/docs/notes.txt
sha256sum ~/fs-lab/docs/notes.txt
~~~

**Task 4: Understand permissions**
~~~bash
chmod 640 ~/fs-lab/docs/notes.txt
ls -l ~/fs-lab/docs/notes.txt
~~~
Explain owner, group, and other permissions.

**Task 5: Inspect storage**
~~~bash
df -h
lsblk -f
findmnt
~~~
Identify the file system for your home directory if it is clear from the output. Do not change partitions or mounts.

### Lab B — Windows

**Task 1: Identify your user and home**
~~~powershell
whoami
$HOME
$env:USERPROFILE
Get-Location
~~~

**Task 2: Explore folders**
~~~powershell
Get-ChildItem C:\ -Force
Get-ChildItem "$HOME" -Force
Get-ChildItem C:\Windows -Directory
~~~
Explain which entries are hidden or protected.

**Task 3: Create and inspect a harmless file**
~~~powershell
New-Item -ItemType Directory -Path "$HOME\fs-lab\docs" -Force
Set-Content "$HOME\fs-lab\docs\notes.txt" "Windows file system practice"
Get-Item "$HOME\fs-lab\docs\notes.txt" | Format-List *
Get-FileHash "$HOME\fs-lab\docs\notes.txt" -Algorithm SHA256
~~~

**Task 4: Inspect permissions**
~~~powershell
Get-Acl "$HOME\fs-lab\docs\notes.txt" | Format-List
icacls "$HOME\fs-lab\docs\notes.txt"
~~~
Write down which users/groups are listed and whether permissions are inherited.

**Task 5: Inspect volumes**
~~~powershell
Get-Volume
Get-PSDrive -PSProvider FileSystem
~~~

### Lab C — Compare both systems

Complete this table using your own results:

| Question | Kali result | Windows result |
|---|---|---|
| User home path | | |
| System root | | |
| Temporary folder | | |
| Main configuration location | | |
| Common log location | | |
| Permission inspection command | | |
| Hash command | | |
| Storage inspection command | | |

### Portfolio project
Create a repository folder such as linux-windows-filesystem-lab/ containing:
- README.md — your explanation and system details.
- screenshots/ — safe screenshots from your own lab.
- notes/linux-findings.md.
- notes/windows-findings.md.
- comparison-table.md.

Do not upload private logs, personal information, passwords, private keys, tokens, or screenshots that expose sensitive system details.

---

## 19. Interview questions and answers

**Q1. What is a file system?**  
A file system is the method an operating system uses to store, organize, locate, and protect files.

**Q2. What is the Linux root directory?**  
It is /, the starting point of the Linux directory tree.

**Q3. Is /root the same as /?**  
No. / is the top of the tree; /root is normally the root administrator's home.

**Q4. What is /etc used for?**  
It contains many system-wide configuration files.

**Q5. What is /var/log used for?**  
It commonly contains system and service logs, though some systems use the systemd journal or other log locations.

**Q6. What is /proc?**  
A virtual file system exposing information about processes and the Linux kernel.

**Q7. What is System32?**  
A Windows folder with important system binaries, libraries, and tools. On 64-bit Windows it commonly contains 64-bit components.

**Q8. Why does 64-bit Windows have SysWOW64?**  
It commonly contains 32-bit Windows components used to support 32-bit applications.

**Q9. What is ProgramData?**  
A common location for application data shared across Windows users.

**Q10. What is AppData?**  
A user-profile location for application settings and data. It commonly includes Local, LocalLow, and Roaming.

**Q11. What is the difference between ext4 and NTFS?**  
ext4 is a common Linux file system; NTFS is a common Windows file system. They have different internal formats, permissions, and features.

**Q12. What is a mount point?**  
A Linux directory where another file system is attached so its contents can be accessed.

**Q13. What does chmod 640 mean?**  
The owner can read and write, the group can read, and other users have no basic mode-bit permissions.

**Q14. What is an NTFS ACL?**  
A set of rules that determines which users or groups can perform specific actions on a file or folder.

**Q15. How can a SOC analyst inspect a file without executing it?**  
Record its path and metadata, inspect its type, calculate a hash, check its signature where supported, and correlate logs. Follow evidence-handling rules.

**Q16. Does a hidden file mean malware?**  
No. Both systems use hidden or protected files for legitimate purposes. Context and behavior matter.

**Q17. Why should an analyst avoid deleting a suspicious file immediately?**  
Deletion may destroy evidence or change the system. Preserve evidence and follow the incident-response process.

**Q18. Why are timestamps not enough to prove what happened?**  
Copying, extraction, synchronization, software behavior, or tampering can affect timestamps. Correlate with other evidence.

---

## 20. Glossary

- **ACL:** Access Control List; a set of rules for access to an object.
- **Absolute path:** Full path starting from a root or volume root.
- **Block device:** Device interface that transfers data in blocks.
- **Directory:** Structure used to organize paths and names.
- **Drive letter:** Windows volume name such as C:.
- **ext4:** Common Linux file system.
- **File metadata:** Information such as size, owner, and timestamps.
- **File system:** Rules and structures for storing and managing files.
- **Hidden file:** A file hidden by a naming convention or attribute; not necessarily protected.
- **Mount:** Attach a file system so it can be accessed.
- **NTFS:** Common Windows file system.
- **Partition:** Defined region of a storage device.
- **Path:** Location of a file or directory.
- **Permission:** Rule controlling access or actions.
- **Root directory:** Top of Linux tree, represented by /.
- **Root user:** Linux superuser account.
- **Symbolic link:** Reference to another path.
- **Volume:** Storage area made available to an operating system.
- **Hash:** A fixed-size result calculated from data, often used to compare exact file content.
- **Least privilege:** Give an account or process only the access needed for its task.

---

## Official references

- Linux Filesystem Hierarchy Standard: https://refspecs.linuxfoundation.org/FHS_3.0/fhs/index.html
- Linux man-pages project: https://man7.org/linux/man-pages/
- Debian Administrator's Handbook: https://www.debian.org/doc/manuals/debian-handbook/
- Microsoft file systems: https://learn.microsoft.com/en-us/windows/win32/fileio/file-systems
- Microsoft file security and access rights: https://learn.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights
- Microsoft icacls command: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls
- Microsoft Get-Acl: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-acl
- Microsoft Sysinternals Sigcheck: https://learn.microsoft.com/en-us/sysinternals/downloads/sigcheck

## Final summary

1. Linux normally starts from /; Windows commonly uses volume roots such as C:\.
2. Linux commonly uses /etc, /home, /usr, and /var; Windows commonly uses C:\Windows, C:\Users, C:\Program Files, and C:\ProgramData.
3. Linux basic permissions use owner/group/other; Windows commonly uses NTFS ACLs.
4. Hidden does not mean secure, and a file extension does not prove a file is safe.
5. SOC analysts inspect metadata, permissions, origin, related events, and context.
6. Practice with harmless files in your own VM before changing system settings or storage.

**Simple learning formula:** Understand the path → Inspect the file → Check permissions → Review context → Document findings.
