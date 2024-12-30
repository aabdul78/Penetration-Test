# Penetration-Test

MegaCorpOne

Confidentiality Statement

This document contains confidential and privileged information from MegaCorpOne Inc. (henceforth known as MegaCorpOne). The information contained in this document is confidential and may constitute inside or non-public information under international, federal, or state laws. Unauthorized forwarding, printing, copying, distribution, or use of such information is strictly prohibited and may be unlawful. If you are not the intended recipient, be aware that any disclosure, copying, or distribution of this document or its parts is prohibited.



Table of Contents:

Confidentiality Statement	2
Contact Information	4
Document History	4
Introduction	5
Assessment Objective	5
Penetration Testing Methodology	6
Reconnaissance	6
Identification of Vulnerabilities and Services	6
Vulnerability Exploitation	6
Reporting	6
Scope	7
Executive Summary of Findings	8
Grading Methodology	8
Summary of Strengths	9
Summary of Weaknesses	9
Executive Summary Narrative	10
Summary Vulnerability Overview	11
Vulnerability Findings	12
MITRE ATT&CK Navigator Map	13


Contact Information:

Company Name	Reliable Security, LLC

Contact Name	Abdihamid Abdullahi

Contact Title	Penetration Tester

Contact Phone	555.224.2411

Contact Email	aabdihamid@reliablesecurity.com


Introduction:

In accordance with MegaCorpOne’s policies, Reliable Security LLC (henceforth known as RS SECURITIES) conducts external and internal penetration tests of its networks and systems throughout the year. The purpose of this engagement was to assess the networks’ and systems’ security and identify potential security flaws by utilizing industry-accepted testing methodology and best practices. The project was conducted on a number of systems on MegaCorpOne’s network segments by RS SECURITIES during July-18-2024.

For the testing, RS SECURITIES  focused on the following:

●	Attempting to determine what system-level vulnerabilities could be discovered and exploited with no prior knowledge of the environment or notification to administrators.
●	Attempting to exploit vulnerabilities found and access confidential information that may be stored on systems.
●	Documenting and reporting on all findings.

All tests took into consideration the actual business processes implemented by the systems and their potential threats; therefore, the results of this assessment reflect a realistic picture of the actual exposure levels to online hackers. This document contains the results of that assessment.

Assessment Objective:

The primary goal of this assessment was to provide an analysis of security flaws present in MegaCorpOne’s web applications, networks, and systems. This assessment was conducted to identify exploitable vulnerabilities and provide actionable recommendations on how to remediate the vulnerabilities to provide a greater level of security for the environment.

RS SECURITIES  used its proven vulnerability testing methodology to assess all relevant web applications, networks, and systems in scope. 

MegaCorpOne has outlined the following objectives:

Table 1: Defined Objectives

Objective:

Find and exfiltrate any sensitive information within the domain.
Escalate privileges to domain administrator.
Compromise at least two machines.


Penetration Testing Methodology


Reconnaissance: 

RS SECURITIES  begins assessments by checking for any passive (open source) data that may assist the assessors with their tasks. If internal, the assessment team will perform active recon using tools such as Nmap and Bloodhound.

Identification of Vulnerabilities and Services:

RS SECURITIES  uses custom, private, and public tools such as Metasploit, hashcat, and Nmap to gain perspective of the network security from a hacker’s point of view. These methods provide MegaCorpOne with an understanding of the risks that threaten its information, and also the strengths and weaknesses of the current controls protecting those systems. The results were achieved by mapping the network architecture, identifying hosts and services, enumerating network and system-level vulnerabilities, attempting to discover unexpected hosts within the environment, and eliminating false positives that might have arisen from scanning. 

Vulnerability Exploitation:

RS SECURITIES ’s normal process is to both manually test each identified vulnerability and use automated tools to exploit these issues. Exploitation of a vulnerability is defined as any action we perform that gives us unauthorized access to the system or the sensitive data. 

Reporting

Once exploitation is completed and the assessors have completed their objectives, or have done everything possible within the allotted time, the assessment team writes the report, which is the final deliverable to the customer.


Scope:

Prior to any assessment activities, MegaCorpOne and the assessment team will identify targeted systems with a defined range or list of network IP addresses. The assessment team will work directly with the MegaCorpOne POC to determine which network ranges are in-scope for the scheduled assessment. 

It is MegaCorpOne’s responsibility to ensure that IP addresses identified as in-scope are actually controlled by MegaCorpOne and are hosted in ping-owned facilities (i.e., are not hosted by an external organization). In-scope and excluded IP addresses and ranges are listed below. 

![image](https://github.com/user-attachments/assets/d7ae8759-d849-46e9-9308-587df6633754)


Executive Summary of Findings

Grading Methodology:

Each finding was classified according to its severity, reflecting the risk each such vulnerability may pose to the business processes implemented by the application, based on the following criteria:

Critical:	 Immediate threat to key business processes.
High:		 Indirect threat to key business processes/threat to secondary business processes.
Medium:	 Indirect or partial threat to business processes. 
Low:		 No direct threat exists; vulnerability may be leveraged with other vulnerabilities.
Informational:    No threat; however, it is data that may be used in a future attack.

As the following grid shows, each threat is assessed in terms of both its potential impact on the business and the likelihood of exploitation:


![image](https://github.com/user-attachments/assets/44b6d40d-d9f9-41f4-ae08-39b67d57ea5a)


Summary of Strengths:

While the assessment team was successful in finding several vulnerabilities, the team also recognized several strengths within MegaCorpOne’s environment. These positives highlight the effective countermeasures and defenses that successfully prevented, detected, or denied an attack technique or tactic from occurring. 

● In the Megacorpone environment I made a few attempts to exploit the network through Metasploit but was unable to use it to successfully connect to any Megacorpone machines.


Summary of Weaknesses:

Reliable Security, LLC successfully found several critical vulnerabilities that should be immediately addressed in order to prevent an adversary from compromising the network. These findings are not specific to a software version but are more general and systemic vulnerabilities.

●	 Administrative credentials were located on the system in plain text.
●	 Port 22 is open.
●	 Weak passwords are allowed and accessible. 
●	 Common Vulnerabilities and Exposures  on apache servers.
●	 Privilege Escalation, to exploit software vulnerabilities, crack passwords for privileged.
●	IP addresses for Megacorpone’s domain servers are publicly available. 
●	 LLMNR, Attackers can exploit LLMNR  to capture credentials or redirect network traffic.


Executive Summary:

Reliable Security successfully accomplished all the objectives outlined in the engagement's scope of work. They managed to identify and extract sensitive data, elevate their privileges to Domain Administrator status, and compromise a minimum of two machines.
The assessment uncovered a few vulnerabilities, with the majority stemming from weak password practices. Through testing, RSecurity was able to exploit weak passwords on both Linux and Windows 10 machines, accessing additional user credentials and data. Subsequently, they escalated their privileges on both systems, establishing backdoor access for ongoing exploitation. This elevated access also enabled lateral movement between machines, including the Domain Controller on Windows systems.
Furthermore, the evaluation exposed vulnerabilities in open ports that could facilitate unauthorized access. During open-source intelligence gathering, RSecurity pinpointed Megacorpone's DNS server IP addresses, potentially exposing them to attacks. Additionally, vulnerabilities related to LLMNR attacks and potential issues with Megacorpone's Apache servers were identified through Shodan reports, although these were not directly tested.
The report's Vulnerability Findings section outlines each vulnerability discovered and provides recommendations for mitigation. While critical areas require immediate attention, most suggested measures are straightforward and cost-effective to implement, emphasizing the importance of addressing weak password practices to significantly reduce risks.


Summary Vulnerability Overview:

![image](https://github.com/user-attachments/assets/be57bf51-5f49-4670-947f-50ddcee59b6b)

The following summary tables represent an overview of the assessment findings for this penetration test:

![image](https://github.com/user-attachments/assets/4067e96f-be97-4c47-8348-79b6838bb424)


Vulnerability Findings:

Weak Password on Public Web Application

Risk Rating: Critical

Description: 

The site vpn.megacorpone.com is used to host the Cisco AnyConnect configuration file for MegaCorpOne. This site is secured with basic authentication but is susceptible to a dictionary attack. Reliable Security, LLC was able to use a username gathered from OSINT in combination with a wordlist in order to guess the user’s password and access the configuration file.

Affected Hosts: vpn.megacorpone.com, 172.22.117.20 – Windows10 machine 172.22.117.10 – WinDC01 – Domain Controller 

Remediation: 

●	Set up two-factor authentication instead of basic authentication to prevent dictionary attacks from being successful.
●	Require a strong password complexity that requires passwords to be over 12 characters long, upper+lower case, & include a special character.
●	Reset the user thudson’s password.

![image](https://github.com/user-attachments/assets/8c9bf612-79fd-40d2-915e-4b6e99c457fc)


CVE vulnerabilities:

Risk Rating: Medium

Description:

We ran a report using Shodan which identified the following potential vulnerabilities on Mascarpone’s Apache servers: CVE-2020-11023, CVE-2019-11358, CVE-205-9251, CVE-2013-4365, CVE-2012-4360, CVE-2011-2288, CVE-2009-2299, CVE-2007-4723.
Affected hosts: Apache servers

Remediation:

● CVE are publicly known security flaws. We did not specifically test to determine if your system has these vulnerabilities but recommend that you learn more about them.
 
 ● Details about these vulnerabilities can be found at:  https://cve.mitre.org/cve/search_cve_list.html

![image](https://github.com/user-attachments/assets/ed314ec9-7feb-4e3d-bc43-d47f8e970e0a)


IP addresses for domain servers are exposed

Risk Rating: Medium

 Description: A search using Recon-ng revealed the IP addresses of Megacorpone’s three NS (named servers). Recon-ng is a publicly available tool so bad actors would also be able to find this information. This may leave Megacorpone vulnerable to DNS poisoning or spoofing where users are directed away from your site and to a malicious site.
Affected hosts: ns1.megacorpone.com, ns2.megacorpone.com, ns3.megacorpone.com

Remediation:

● Make the IP addresses for these servers private

● If you choose for the IP addresses to remain public you’ll need to ensure that servers are up to date and have strong firewall protections in place.



Privilege Escalation

Risk Rating: High

 Description:
 
 Privilege escalation is an additional issue related to weak passwords. While resolving weak passwords should reduce the risk, taking action to specifically prevent escalation of privileges if access is gained is also important.

Affected hosts: 172.22.117.10 – Linux machine

172.22.117.20 – Windows10 machine

Remediation:

● Enforce strong password policies, including regular password changes and the use of complex passwords to prevent unauthorized access.
● Patch and update systems to protect against known malicious content.
● Use vulnerability scanning tools. 
 
Escalating user access privileges:

![image](https://github.com/user-attachments/assets/143c6eb3-3a30-428f-9159-586fdeedf864)
![image](https://github.com/user-attachments/assets/cc1e86c0-77e9-4bf2-aedb-75315a99233c)
![image](https://github.com/user-attachments/assets/e93d6252-c74d-41b7-8c2e-b7cde01ca972)

Port 22 is open

Risk Rating: critical

Description:

A Zenmap scan revealed that port 22  is open on Windows machine 172.22.117.20. There are known tools to use  with this port that makes them vulnerable to backdoor attacks that will allow attackers to establish a persistent connection with the machine so that they can exploit its data.
Affected hosts: Windows machine 172.22.117.20

Remediation:

● Enable logging for FTP services to track and monitor user activity or Close port 21.
● Correct weak password issue mentioned above
● Keep your FTP server software up to date with the latest security patches to address known vulnerabilities and prevent exploitation.
● Use advanced antivirus/antimalware and keep it up-to-date
● Configure firewalls to restrict access to port 21

![image](https://github.com/user-attachments/assets/3f2e6865-637c-417d-b4c3-e4cdc608a63f)
![image](https://github.com/user-attachments/assets/db6f68fc-3db8-4d81-8af9-8a7e116b615f)
![image](https://github.com/user-attachments/assets/28c44114-c3d0-44eb-9ffb-ebfeb13b5287)
![image](https://github.com/user-attachments/assets/04aa8eeb-3959-4dec-a929-96968446992a)
![image](https://github.com/user-attachments/assets/c9c13549-f98d-43e5-9c84-8de78fc8acf2)
![image](https://github.com/user-attachments/assets/0aa0475a-f752-4bf5-a698-97988c142a23)
![image](https://github.com/user-attachments/assets/0d1d13ac-b064-4660-a389-8851367a8f60)
![image](https://github.com/user-attachments/assets/7b9a75c0-9352-43ed-bd6d-b0477ae16d22)


Created Backdoor on the Window Machine

![image](https://github.com/user-attachments/assets/ddd20e1b-9f0d-454c-b4b5-a895858282a0)


MITRE ATT&CK Navigator Map:


The following completed MITRE ATT&CK navigator map shows all of the techniques and tactics that RS SECURITIES  used throughout the assessment.

![image](https://github.com/user-attachments/assets/7bbc9cf2-4e47-4345-9825-6e78ff582d9a)

Performed successfully (Yellow)

Failure to perform (Red)














