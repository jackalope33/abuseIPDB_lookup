# abuseIPDB_lookup
Small Bash script for querying AbuseIPDB API

This is a basic bash script for querying the AbuseIPDB API. 

Usage: ./abuseipdb_check.sh <file>.txt
(where file contains a list of IP addresses to be checked)

Input: File with list of IP addresses
Output: CSV file including the following fields:
  IP Address
  Public
  White Listed
  Confidence Score
  Country
  ISP
  Domain
  Total Reports
  Last Reported
  
The scripts creates two directories:
json_results/ : Contains json files of all IPs with confidence score greater than 0
results/ :      Contains csv file of all results

Important Note: In order to use this script, you must register with Abuseipdb.com for an API key
  (Enter the API key in line 3, after "api_key=")
