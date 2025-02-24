# Wazuh Hybrid Integration

This script integrates Wazuh with Hybrid Analysis, enhancing the analysis of files based on MD5 hashes from Sysmon and Syscheck alerts. It works by extracting the MD5 hash from these alerts and generating a request to Hybrid Analysis for further malware insights. The script automatically triggers when these specific alerts are generated, improving detection and response capabilities.

##Important: No files are uploaded to Hybrid Analysis. Instead, the integration queries Hybrid Analysis using public reports uploaded by other users for the same MD5 hash, providing malware insights without sharing sensitive files.

##Key Features:
* Sysmon & Syscheck Integration: Works with Sysmon and Syscheck alerts, utilizing the MD5 hash extracted from the alert data to query Hybrid Analysis. You need a agent with sysmon installed more info: https://wazuh.com/blog/using-wazuh-to-monitor-sysmon-events/
* Public Hybrid Analysis Reports: The integration queries public Hybrid Analysis reports associated with the MD5 hash, without uploading any files.
Improved Threat Detection: By leveraging Hybrid Analysis’ malware intelligence, the script enhances Wazuh’s security monitoring and threat detection capabilities.

##Prerequisites:
* Hybrid Analysis Account: You need a Hybrid Analysis account and an API key to use this integration. You can sign up and obtain your API key from Hybrid Analysis.

##Instalation:
* Download the custom-hybrid.py file and add it into integrations folder (Example: /var/ossec/integrations)
* Modify your ossec.conf adding the lines present in the ossec.conf provided in this repository
* Add the provided custom rules file (/var/ossec/etc/rules/)
* Restart Wazuh Manager
