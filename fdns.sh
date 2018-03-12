curl -s 'https://scans.io/_d/data/rapid7/sonar.fdns_v2/2018-02-04-1517731201-fdns_any.json.gz' | pigz -dc \
 | grep -P "\.$1" \
 | jq -r '.name' \
 | tee fdnsx-$1.txt
