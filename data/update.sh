wget https://github.com/DustinWin/clash_singbox-tools/releases/download/mihomo/mihomo-alpha-linux-amd64.tar.gz -O - | tar -zxf - -C ./tools/
mv -f ./tools/CrashCore ./tools/mihomo
wget https://github.com/DustinWin/clash_singbox-tools/releases/download/sing-box/sing-box-release-linux-amd64v3.tar.gz -O - | tar -zxf - -C ./tools/
mv -f ./tools/CrashCore ./tools/sing-box
curl -L -O https://github.com/Qerleng/00/raw/main/sing-box/v2dat
mkdir -p ./test/
mv -f ./v2dat ./tools/


rm sing-box v2dat mihomo CrashCore
