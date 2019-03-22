archive() {
	
	curl -s 'http://web.archive.org/cdx/search?url='$1'%2F&matchType=prefix&collapse=urlkey&output=json&fl=original%2Cmimetype%2Ctimestamp%2Cendtimestamp%2Cgroupcount%2Cuniqcount&filter=!statuscode%3A%5B45%5D..&limit=100000&_=1532513891577' --compressed | grep -Po "(?<=\[\").*?(?=\")"

}
