## Alert #1
**Date:** 2026-10-19
**Alert Title:** SOC101 - Phishing Mail Detected
**Severity:** Medium
**Source:** Free-domain email (Gmail) with random numeric suffix
**Target:** user@example.com

**Hypothesis:** Phishing attempt using urgency-based social engineering

**Evidence:**
- Sender used a free Gmail address with a random numeric suffix
- Subject line used urgency/curiosity bait tactics
- Device Action showed "Allowed" — email reached the inbox

**Classification:** True Positive - Malicious
**Action Taken:** Flagged for user awareness, recommended sender block
**Time to Triage:** ~10 minutes

**IOCs:** Free-mail sender pattern, urgency-themed subject line

---

## Alert #2
**Date:** 2026-10-19
**Alert Title:** SOC101 - Phishing Mail Detected
**Severity:** Medium
**Source:** Spoofed domain impersonating a financial institution ("Company X Bank")
**Target:** user@example.com

**Hypothesis:** Financial-themed phishing attempting credential or data theft

**Evidence:**
- Sender domain impersonated a bank but had no verified legitimacy
- Subject referenced a "Credit Card Statement" (common financial lure)
- Alert was pre-mapped to MITRE ATT&CK T1053.005
- Device Action showed "Blocked" — defense system intercepted it

**Classification:** True Positive - Malicious (Blocked)
**Action Taken:** No action needed — email was automatically blocked
**Time to Triage:** ~8 minutes

**IOCs:** Spoofed-bank domain, financial-themed subject, T1053.005 pattern

---
## Alert #3
**Date:** 2023-06-21
**Alert Title:** SOC210 - Possible Brute Force Detected on VPN
**Severity:** High
**Source:** External IP (VPN/hosting provider) - redacted as 203.0.113.x
**Target:** VPN gateway (internal, redacted as 10.x.x.x)

**Hypothesis:** Password spraying + username enumeration via automated tool

**Evidence:**
- 10 login attempts in 8 minutes, mixed "unknown username" and
  "wrong password" responses (enumeration + spraying pattern)
- 10th attempt succeeded on a valid account
- IP reputation clean on VirusTotal, but sourced from a commercial
  VPN/hosting provider commonly abused for this attack type
- Scope confirmed: single target system, no lateral spread

**Classification:** True Positive - Malicious
**Action Taken:** Isolated compromised account, blocked attacker IP,
recommended MFA enforcement and account lockout policy
**Time to Triage:** ~25 minutes
**IOCs:** Attacker IP (redacted), mixed-failure login pattern, VPN
gateway (redacted)

---
## Alert #4
**Date:** 2025-03-13
**Alert Title:** SOC338 - Lumma Stealer DLL Side-Loading via ClickFix Phishing
**Severity:** Critical
**Source:** Spoofed domain impersonating Microsoft (redacted as "Company X")
**Target:** user@example.com

**Hypothesis:** ClickFix-style phishing leading to malware (Lumma Stealer) deployment

**Evidence:**
- Email impersonated a Microsoft domain (confirmed malicious by
  12/93 vendors on VirusTotal), offered free Windows 11 upgrade
- Device Action: Allowed - email reached the inbox
- Log Management confirmed outbound C2 communication from the
  recipient's device (initial search missed this - see note below)
- EDR containment found multiple malicious .exe files actively
  running on the endpoint
- Alert mapped to 8 MITRE ATT&CK techniques covering the full
  ClickFix kill chain (T1204, T1204.001, T1574, T1574.002, T1059,
  T1059.001, T1027, T1105)

**Classification:** True Positive - Malicious (Confirmed Compromise)
**Action Taken:**
1. Deleted malicious email from recipient's mailbox
2. Isolated affected device via EDR
3. Identified and will investigate multiple malicious executables
**Time to Triage:** ~35 minutes
**IOCs:** Spoofed domain (redacted), SMTP address (redacted), Lumma
Stealer malware family, ClickFix technique, multiple .exe payloads

**Analyst Note:** Initial log search for C2 activity returned no
results due to insufficient date-range scope. Re-running the search
with corrected parameters confirmed the compromise. Lesson: a
negative log search result is not conclusive without verifying
search scope first.

---
## Alert #5
**Date:** 2025-01-22
**Alert Title:** SOC335 - CVE-2024-49138 Exploitation Detected
**Severity:** Medium
**Source:** Local host (redacted as "Host A")
**Target:** N/A (local privilege escalation, not network-based)

**Hypothesis:** Privilege escalation via masquerading malware exploiting CVE-2024-49138

**Evidence:**
- Malicious file "svohost.exe" masqueraded as legitimate
  "svchost.exe", executed from non-standard path (C:\temp\...)
- Spawned by powershell.exe; file hash confirmed malicious on
  VirusTotal
- EDR showed the process subsequently spawned its own PowerShell
  child process running under NT AUTHORITY\SYSTEM (confirmed
  privilege escalation)
- VirusTotal sandbox behavior showed only legitimate Microsoft
  domains and local network traffic - no clear C2 indicator
  (treated as inconclusive, not definitive)
- MITRE: T1059.001, T1055, T1068, T1548, T1110

**Classification:** True Positive - Malicious (Confirmed privilege escalation)
**Action Taken:** Host contained via EDR; recommended patching
against CVE-2024-49138 and direct Log Management review for C2
**Time to Triage:** ~15 minutes
**IOCs:** File hash:
b432dcf4a0f0b601b1d79848467137a5e25cab5a0b7b1224be9d3b6540122db9;
masquerading filename pattern (svohost.exe vs svchost.exe);
non-standard execution path (C:\temp\service_installer\)

---
