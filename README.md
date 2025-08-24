🛡️ IR Playbook – 1.2: Brute Force Attack Detection
--


📖 Overview
-
This project demonstrates how to detect, investigate, and respond to Brute Force attacks on Windows authentication logs using Splunk SPL queries. The playbook is mapped to the MITRE ATT&CK framework to ensure standardized adversary behavior tracking.

The detection focuses on identifying excessive failed logon attempts (EventID=4625), analyzing patterns of attack (e.g., password spraying vs. credential stuffing), and correlating with successful logins (EventID=4624) to spot potential compromises.

By combining baseline detection, enrichment, threat hunting patterns, and threat intelligence lookups, this playbook provides a complete detection-to-response workflow for brute force attacks.

🔑 Key Benefits:

Detect brute force attempts in real-time.

Differentiate attack strategies (spraying vs. stuffing).

Enrich with IP geolocation & threat intelligence feeds.

Provide structured IR investigation & response steps.

Automate alerts for SOC teams.




📌 MITRE ATT&CK Mapping
• T1110 – Brute Force (Password Guessing)
• T1078 – Valid Accounts (Goal is to obtain valid credentials)
-
1️⃣ Detection – Find Excessive Failed Logons

sql

index="sim1" sourcetype="csv" source="SecurityLogs_MITRE_Advanced_sample.csv" EventID=4625
| stats count by Source_IP, Account_Name
| where count >= 5
| sort - count

👉 This baseline query identifies source IPs with 5 or more failed authentication attempts against any account. Adjust the count >= 5 threshold based on your environment's normal noise level.


<img width="1222" height="887" alt="1 Detection – Find_excessive_failed_logons" src="https://github.com/user-attachments/assets/c12fce10-5004-4702-bc1f-88afc2093f73" />


========================================================================================================================================================================================

2️⃣ Enrichment – Add Context to the Attacks


Now we expand: When did this happen? What was the target?


sql

index="sim1" sourcetype="csv" source="SecurityLogs_MITRE_Advanced_sample.csv" EventID=4625
| stats count earliest(_time) as First_Attempt latest(_time) as Last_Attempt by Source_IP, Account_Name
| eval Duration = Last_Attempt - First_Attempt
| where count >= 5
| sort - count


🔍 This gives:
•	Source_IP: The attacking host.
•	Account_Name: The target user account.
•	count: Total number of attempts.
•	First_Attempt, Last_Attempt, Duration: The timeframe of the attack campaign.

<img width="1228" height="903" alt="2 Enrichment – Add Context to the Attacks" src="https://github.com/user-attachments/assets/dabf3859-0bb4-4a09-959c-58724ac4a1a6" />

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------


3️⃣ Threat Hunting – Identify Attack Patterns
Categorize the attacks to understand the adversary's strategy.

sql

index="sim1" sourcetype="csv" source="SecurityLogs_MITRE_Advanced_sample.csv" EventID=4625
| stats count dc(Account_Name) as Targeted_Users by Source_IP
| where count >= 5
| eval Attack_Type=case(Targeted_Users==1, "Password Spraying", Targeted_Users>1, "Credential Stuffing/Brute Force")
| sort - count


👉 Key Insight:
•	Password Spraying (Targeted_Users==1): Many attempts against a single account. Indicates the attacker may know a username.
•	Credential Stuffing/Brute Force (Targeted_Users>1): Fewer attempts against many accounts. Indicates the attacker is trying common passwords across the domain.



<img width="1227" height="829" alt="3 Threat Hunting – Identify Attack Patterns" src="https://github.com/user-attachments/assets/b7be050f-2d6d-4e48-9a73-0ac74009b866" />

---------------------------------------------
4️⃣ Threat Intel – External Reputation Check
Enrich the attacking IPs with threat intelligence.

spl

index="sim1" sourcetype="mitre_logs" EventID=4625
| stats count by Source_IP, Account_Name
| where count >= 5
| iplocation Source_IP
| table Source_IP, City, Country, count, Account_Name

👉 Now you’ll see the geolocation of the source IP  with City, Country, count, Account_Name



<img width="1229" height="907" alt="4  Threat Intel – External Reputation Check" src="https://github.com/user-attachments/assets/57c42eef-7e54-4af8-9717-da179e67a947" />

-------------------------------------------------------------
5️⃣ IR Investigation Steps
When a brute force attack is detected:
1.	Confirm the Target(s): Identify the user account(s) being targeted. Are they high-value (e.g., Administrator, domain admins, service accounts)?


2.	Check for Success: Immediately search for a successful login (EventID=4624) from the same Source_IP immediately following the failure spike.

sql
index="sim1" (EventID=4624 OR EventID=4625) Source_IP="192.168.212.28"
| transaction Source_IP, Account_Name startswith=(EventID=4625) endswith=(EventID=4624)
| table _time, Source_IP, Account_Name, EventID


3.	Review Account Activity: If a success is found, investigate what that account did immediately after logging in (other events from that user session).
4.	Check IP Reputation: Manually look up the IP in AbuseIPDB, VirusTotal, etc.


<img width="1230" height="902" alt="5  IR Investigation Steps" src="https://github.com/user-attachments/assets/6dc0376f-1354-47c0-af7d-09c1c2fa4002" />

----------------------------------------------------------
6️⃣ Response Actions

•	If Malicious & Ongoing:
1.	Block the IP at the network perimeter (firewall) or host level (Windows Firewall via GPO).
2.	Force password reset for any potentially compromised accounts.
3.	Alert the targeted users to be vigilant and report any suspicious activity.
4.	If a successful login occurred, initiate your incident response protocol for compromised accounts.

•	If Benign:
o	Could be a misconfigured service or script. Document the exception and tune the alert to exclude that source IP if appropriate

-------------------------------------------------

7️⃣ Alerting – Make it Continuous

Create a scheduled Splunk alert:
•	Search: The base detection query.
•	Schedule: Run every 10 minutes.
•	Trigger Condition: where count >= 5
•	Action: Send an alert to your SIEM/SOC channel with details: Source_IP, Account_Name, count, and a link to investigate.

<img width="838" height="853" alt="alert_1 2_bruteforce2" src="https://github.com/user-attachments/assets/7907bde5-2b49-40b4-aff2-c6d668227af0" />

----

<img width="1226" height="686" alt="alert_1 2_bruteforec1" src="https://github.com/user-attachments/assets/2f261142-68ee-4cd1-b18c-1b7ce6eb1287" />

=============================







Requirements
--

Splunk Enterprise 8.x or newer

Windows Security event logs indexed in Splunk

Basic understanding of SPL and MITRE ATT&CK framework

About Me I am a cybersecurity enthusiast specializing in detection engineering and threat hunting using Splunk. This repository demonstrates my practical skills aligned with real-world attack techniques.

Contact For questions or collaboration, reach me at: Email: moglibd22@gmail.com GitHub: tuh1n-bd

Thank you for visiting my repository!

