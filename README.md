# Incident-Response-Playbook-




###🛡️ IR Playbook – 1.2 - Brute Force Attack Detection (Windows Authentication Failures)
-
📌 MITRE ATT&CK Mapping
• T1110 – Brute Force (Password Guessing)
• T1078 – Valid Accounts (Goal is to obtain valid credentials)

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
