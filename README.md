# abuseIPDB_lookup
**Small Bash script for querying AbuseIPDB API**

This is a basic bash script for querying the AbuseIPDB API. 

Before first run, make script executable (chmod +x abuseipdb_lookup.sh)

**Usage:** 
  - ./abuseipdb_lookup.sh \<ip address\>
(where file contains a list of IP addresses to be checked)
  - ./abuseipdb_lookup.sh -f \<file\>

**Input:** File with list of IP addresses/hostnames

**Output:** CSV file including the following fields:
- IP Address
- Public
- White Listed
- Confidence Score
- Country
- ISP
- Domain
- Total Reports
- Last Reported
  
  
  
**The scripts creates two directories:**
- json_results/ : Contains json files of all IPs with confidence score greater than 0
- results/ :      Contains csv file of all results


*Important Note: In order to use this script, you must register with Abuseipdb.com for an API key*
- Upon first run, you will be prompted for the API key
