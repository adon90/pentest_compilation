#!/bin/sh

cert (){

org=$@;
org=$(echo "$org" | sed 's/ /+/g');
b=$(curl -ks "https://crt.sh/?O=$org" | grep -Po "(?<=\?id=).*(?=\")"); for i in $b; do curl -ks "https://crt.sh/?id=$i" | grep -Po "(?<=DNS:).*?(?=<BR)"; done
}

cert $@
