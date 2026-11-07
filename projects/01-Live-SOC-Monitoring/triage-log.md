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
