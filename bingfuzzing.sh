#!/bin/bash

# Extracts URLs from the first Bing page

bingfuzzing () {

	if [ "$#" -ne 2 ]; then
	     echo "Usage: bingfuzzing <domain> <wordlist>"
	     return
	fi
	
	cat $2 | xargs -n1 -P8 bash -c 'i=$0; url="https://www.bing.com/search?q=domain%3a'$1'%20${i}&first=1"; curl -s $url | grep -Po "(?<=<a href=\").*?(?=\" h=)" | egrep -v "microsoft|bing|pointdecontact|youtube\.com" | grep -Po "https?.*" | grep "'$1'"'


}

bingfuzzing $1 $2
