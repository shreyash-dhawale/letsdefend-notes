# LetsDefend Alert Investigation — 22 July 2026

## Alert Details

| Field          | Value |
|----------------|-------|
| Alert Name     |EventID: 235 - [SOC127 - SQL Injection Detected]       |
| Severity       |High       |
| Source IP      |118.194.247.28       |
| Destination IP |172.16.20.12       |
| Alert Time     |Mar, 07, 2024, 12:51 PM      |
| My Verdict     |True Positive |

---

## Investigation Steps

### Step 1 — Initial alert review
What the alert said: At Mar, 07, 2024, 12:51 PM, SQL Injection Attack exploits to target IP 172.16.20.12 by 118.194.247.28.
What I noticed immediately: The request URL is surely looking the malicious link coated by some SQL queries.

### Step 2 — IP reputation check
VirusTotal result for source IP: The score is 10/91 which look like malicious but in relation tab, no malicious activity.
Hybrid Analysis result: It specifies that is clean.
Conclusion from reputation check: After the both the analysis, it concluding that it is clean.

### Step 3 — Log analysis
What the raw logs showed: The raw logs shows that at 12:53 PM, executes the SQL Injection by updating it to malicious queries. 
Key evidence found: At 12:53:11, the attacker exploits the database to gain data and after that it is accessing through the existing user.

### Step 4 — Related events
Other alerts from same IP: The attacker 118.194.247.28 is tries only in one id and exploiting from their only.
Pattern noticed: The attacker infiltrate the only one the user and certain amount of operations via same url.

---

## Verdict

**True Positive**

Why I made this decision: Based on the analysis, it shows that the sender IP is clean and after the reviewing the log data, I suspect that in the couple of logs their is some abnormal queries are execute. So, the True Positive is most likely considered for this alert.

---

## ATT&CK Technique Mapping

| Technique ID | Name | Evidence |
|---|---|---|
| T1190 |Exploit Public-Facing Application |exploits the web application |

---

## What I Would Do Next

If this is a True Positive — next steps:
1. Review web server, WAF, IDS/IPS, firewall, and database logs.
2. Identify the vulnerable URL and parameter.
3. Determine whether the attack was blocked or successful.

---

## Splunk Detection Rule

If I had Splunk monitoring this environment I would detect
this alert with:

```spl
index=main sourcetype=firewall OR sourcetype=apache OR sourcetype=nginx
earliest=-55m latest=now
(
    uri="*id=*"
    AND
    (
        uri="*'*"
        OR uri="*UNION*"
        OR uri="*SELECT*"
        OR uri="*OR*1=1*"
        OR uri="*--*"
        OR uri="*SLEEP(*"
        OR uri="*WAITFOR*"
    )
)
| stats count values(uri) as Target_URL values(http_method) as Method by src_ip dest_ip
| where count>=2
| sort -count
```
