#!/bin/bash
date=$(date | sed s/[" ":]/_/g | cut -c -19)
api_key=

if [ -z $1 ]; then
	printf "Usage: ./abuseipdb_check.sh <file>.txt \n(where file contains a list of IP addresses to be checked)\n\nNo file listed...exiting.\n"
	exit 1
fi

mkdir results 2> /dev/null
mkdir json_results 2>/dev/null
let c=0
let m=0

printf "IP Address,Public,White Listed,Score,Country,ISP,Domain,Total Reports,Last Reported\n" | tee results/abuse_results_$date.csv > /dev/null

for ip in $(cat $1 | sort | uniq); do
	curl -G https://api.abuseipdb.com/api/v2/check \
	  --data-urlencode "ipAddress=$ip" \
	  -d maxAgeInDays=90 \
	  -d verbose \
	  -H "Key: $api_key" \
	  -H "Accept: application/json" >> $ip.json

	isPublic=$(cat $ip.json | awk -F, '{print $2}' | cut -c 12-)
	isWhitelisted=$(cat $ip.json | awk -F, '{print $4}' | cut -c 17-)
	score=$(cat $ip.json | awk -F, '{print $5}' | cut -c 24-)
	countryName=$(cat $ip.json | awk -F, '{print $10}' | cut -c 15-)
	isp=$(cat $ip.json | awk -F, '{print $8}' | cut -c 7-)
	domain=$(cat $ip.json | awk -F, '{print $9}' | cut -c 10-)
	totalReports=$(cat $ip.json | awk -F, '{print $11}' | cut -c 16-)
	lastReportedAt=$(cat $ip.json | awk -F, '{print $12}' | cut -c 18-)

	echo $ip","$isPublic","$isWhitelisted","$score","$countryName","$isp","$domain","$totalReports","$lastReportedAt >> results/abuse_results_$date.csv

	if [ $score -gt 0 ]; then
		mv $ip.json json_results/
		echo **MALICIOUS SITE FOUND**: $ip
		let m+=1
	else
		rm -f $ip.json 2> /dev/null
		fi
	let c+=1
done

cat results/abuse_results_$date.csv | egrep -i 'true|false|public' > results/results_$date.csv && rm results/abuse_results_$date.csv

printf "\n\t\t\t\tSummary"
printf "\n====================================================================="
printf "\nTotal Sites Checked:\t\t\t%d" $c
printf "\nMalicious Sites Found:\t\t\t%d\n\n" $m
printf "CSV report:\t\tresults/results_$date.csv\n"
printf "Full json output:\tjson_reports/\n\n"
