archive() {
	
	curl -s 'http://web.archive.org/cdx/search?url='$1'%2F&matchType=prefix&collapse=urlkey&output=json&fl=original%2Cmimetype%2Ctimestamp%2Cendtimestamp%2Cgroupcount%2Cuniqcount&filter=!statuscode%3A%5B45%5D..&limit=100000&_=1532513891577' --compressed | grep -Po "(?<=\[\").*?(?=\")"

}

bing() {

	curl "https://www.bing.com/search?q=domain%3a$1&first=1" -s |  grep -Po "(?<=<a href=\").*?(?=\" h=)" | egrep -v "microsoft|bing|pointdecontact" | grep -Po "https?.*"

}


google() {

	curl -i -s -k  -X $'GET'   -H $'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:63.0) Gecko/20100101 Firefox/63.0' -H $'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H $'Connection: close'     $'https://www.google.to/search?q=site:$1&num=60' -x socks4://127.0.0.1:1337 | grep -Po "(?<=<a href=\").*?(?=\" onmousedown=)" | grep -v data-ved

}

# Usage: archive <domain> or bing <domain> or google <domain> (this last one is suppossed to be launched with doxycannon to bypass google captcha)
