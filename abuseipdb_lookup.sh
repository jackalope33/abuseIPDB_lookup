#!/bin/bash
date=$(date | sed s/[" ":]/_/g | cut -c -19)

# Exit if no arguments passed
if [ -z $1 ]; then
	printf "Usage:\n  ./abuseipdb_lookup.sh [<ip>] [-f <file>] [--help]\n"
	exit 1
fi

# Check for jq. If not present, prompt for installation.
jq 2> /dev/null
if [[ $? == "127" ]]; then
	printf "jq not installed. Please run the following command to install.\n\tDebian: apt-get install jq\n\tRed Hat: yum install jq\n\tMac: brew install jq\n"
	exit
fi

# Check for API key. If not present, prompt for key
if [ ! -f ".abuse_apikey" ]; then
	printf "No API key found. Please enter API key: "
	read api_key

	# Input validation -- ensure the API key is the correct length. Exit if not
	if [ $(echo $api_key | wc -c) -ne 81 ]; then
		printf "\nAPI key has invalid length. Exiting.\n"
		exit
	fi
	# Store the API key in a hidden file accessible only to the owner
	echo $api_key > .abuse_apikey
	chmod 600 .abuse_apikey
	sleep 1
	printf "\nAPI key stored.\n" && sleep .5
else
	api_key=$(cat .abuse_apikey)
fi

# Name lookup function
name_look () {
	nslookup $1 8.8.8.8 | grep Address | grep -v '#53' | awk '{print $2}' | head -1
	return 0
}

# Function for API call -- uses curl to obtain json record of IP being queried
# Parses syntax and assigns variable values using awk
api_call () {
	ip=$1

	# Regex to check if IP contains letters
	site_check='[A-Za-z]'
	if [[ $1 =~ $site_check ]]; then

		# If letters detected, look up IP address
		printf "\nLooking up IP..."
		ip=$(name_look $ip)
		if [ -z $ip ]; then
			printf "\nNo IP registered for host %s. Skipping" $1
			let skip=1
			return 1
		fi
		printf "Checking %s..." $ip
	fi
	curl -G -s https://api.abuseipdb.com/api/v2/check \
		--data-urlencode "ipAddress=$ip" \
		-d maxAgeInDays=90 \
		-d verbose \
		-H "Key: $2" \
		-H "Accept: application/json" >> $ip.json

		isPublic=$(cat $ip.json | jq -r '.["data"].["isPublic"]')
		isWhitelisted=$(cat $ip.json | jq -r '.["data"].["isWhitelisted"]')
		score=$(cat $ip.json | jq -r '.["data"].["abuseConfidenceScore"]')
		countryName=$(cat $ip.json | jq -r '.["data"].["countryName"]')
		isp=$(cat $ip.json | jq -r '.["data"].["isp"]')
		domain=$(cat $ip.json | jq -r '.["data"].["domain"]')
		totalReports=$(cat $ip.json | jq -r '.["data"].["totalReports"]')
		lastReportedAt=$(cat $ip.json | jq -r '.["data"].["lastReportedAt"]')

		# Checks status code of API response. Exits if site unavailable
		if [ $(cat $ip.json | awk -F, '{print $1}' | cut -c 23-) -eq 1 ] 2>/dev/null ; then
			printf "\nAbuseIPDB API is down. Please try again later.\nExiting...\n"
			rm -f $ip.json
			exit
		fi
	return 0
}

case $1 in
	-f)
		let file=1
		# Creates directories for csv/json files and suppresses STDERR if directories already exist
		mkdir results 2> /dev/null
		mkdir json_results 2>/dev/null

		# Initialize counter variables and determine number of unique IPs
		let c=0
		let m=0
		t=$(cat $2 | uniq | wc -l)

		# Create header line for csv report
		printf "IP Address,Public,White Listed,Score,Country,ISP,Domain,Total Reports,Last Reported\n" | tee results/abuse_results_$date.csv > /dev/null

		# For loop for each IP address - performs API call and assesses based on confidence value (greater than 0)
		for ip in $(cat $2 | sed s/'\r'//g | sort | uniq); do
			let skip=0
			let c+=1
			printf "\n%s of %s:\tChecking %s" $c $t $ip
			api_call $ip $api_key
			if [ $skip -eq 1 ]; then
				continue
			fi
			echo \"$ip\"","\"$isPublic\"","\"$isWhitelisted\"","\"$score\"","\"$countryName\"","\"$isp\"","\"$domain\"","\"$totalReports\"","\"$lastReportedAt\" >> results/abuse_results_$date.csv
			if [ "$score" -gt 0 ]; then
				mv $ip.json json_results/
				printf "\t**MALICIOUS**"
				let m+=1
			else
				rm -f $ip.json 2> /dev/null
			fi
		done

		# Outputs only valid records to final report (including header value)
		cat results/abuse_results_$date.csv | egrep -i 'true|false|public' > results/results_$date.csv && rm results/abuse_results_$date.csv

		# Report Summary displayed to STDOUT
		printf "\n\t\t\t\tSummary"
		printf "\n====================================================================="
		printf "\nTotal Sites Checked:\t\t\t%d" $c
		printf "\nMalicious Sites Found:\t\t\t%d\n\n" $m
		printf "CSV report:\t\tresults/results_$date.csv\n"
		printf "Full json output:\tjson_reports/\n\n"
		;;
	--help)
		# Help text
		clear
		printf "\t=============================\n"
		printf "\t| Abuse IPDB Lookup Utility |\n"
		printf "\t=============================\n\n"
		printf "This is a basic utility that queries the Abuse IPDB for IP addresses that have been reported as malicious.\n"
		printf "\nArguments:\n\t<ip>:\tPassing a single IP address as an argument will perform\n\t\ta single lookup. Results are displayed as standard output.\n"
		printf "\n\t\tex: ./abuseipdb_lookup.sh 123.123.123.123\n"
		printf "\n\t-f:\tThe file argument requires a file containing a list of IP addresses\n\t\tto be specified. Results are saved as a csv file.\n\n\t\tex: ./abuseipdb_lookup.sh -f list.txt\n\n"
		;;
	*)
		let file=0
		# Single query of API using IP address passed as command line argument
		printf "\nChecking %s..." $1
		api_call $1 $api_key
		if [ -z "$score" ]; then
			printf "\n\nInvalid response for %s. Exiting.\n" $1
		else
			if [ "$score" -eq 0 ]; then
				printf "\n\n%s has either not been reported as suspicious/malicious or has been whitelisted.\n" $1
			else
			printf "\n\n%s has been reported as malicious!\n\n" $1
			sleep 1
			printf "Domain:\t\t\t%s\n" $domain
			printf "Country:\t\t%s\n" "$countryName"
			printf "ISP:\t\t\t%s\n" "$isp"
			printf "Confidence Score:\t%s\n" $score
			printf "Total Reports:\t\t%s\n" $totalReports
			printf "Last Reported:\t\t%s\n\n" $lastReportedAt
			fi
		fi
		rm -f $1.json 2> /dev/null
		;;
esac
