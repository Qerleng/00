#!/bin/bash

set -e -o pipefail

VERSION=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest \
| grep tag_name \
| cut -d ":" -f2 \
| sed 's/\"//g;s/\,//g;s/\ //g;s/v//')

curl -Lo sing-box.tar.gz "https://github.com/SagerNet/sing-box/releases/download/v${VERSION}/sing-box-${VERSION}-linux-amd64.tar.gz"
curl -Lo geoip.db "https://github.com/rfxcll/v2ray-rules-dat/releases/latest/download/GeoIP.db"
curl -Lo geosite.db "https://github.com/rfxcll/v2ray-rules-dat/releases/latest/download/GeoSite.db"

tar -xzvf sing-box.tar.gz
# mv ./sing-box-${VERSION}-linux-amd64/sing-box .
chmod +x sing-box

geoipAddresses=( "id" "facebook" "google" "netflix" "telegram" "twitter")
geositeDomains=("oisd-full" "oisd-nsfw" "rule-ads" "oisd-small" "rule-doh" "rule-gaming" "rule-indo" "rule-playstore" "rule-sosmed" "rule-streaming" "rule-umum" "rule-ipcheck" "rule-speedtest" "videoconference" "rule-malicious" "urltest" "openai" "ecommerce-id" "bank-id")

for item in "${geoipAddresses[@]}"; do
    ./sing-box geoip export "$item"
done

for item in "${geositeDomains[@]}"; do
    ./sing-box geosite export "$item"
done

for item in *.json; do
    ./sing-box rule-set compile "$item"
    mv "${item%.json}.srs" bin/
    mv "$item" rule-set/
done

rm -rf sing-box.tar.gz sing-box-${VERSION}-linux-amd64/ geoip.db geosite.db sing-box
