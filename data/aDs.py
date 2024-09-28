import requests
import ipaddress

def get_rule_update(url):
    try:
        r = requests.get(url)
        update_rule_update = r.text.split("\n")
        update_rule_update = [line.replace("  - DOMAIN,", "").replace("  - DOMAIN-SUFFIX,", "").replace("  - IP-CIDR,", "").replace("||", "").replace("|", "").replace("://", "").replace("127.0.0.1 ", "").replace("0.0.0.0 ", "").replace("^", "") for line in update_rule_update if not line.startswith(('#', '!', '/', '@', '-', '&', 'payload:'))]
        domains = []
        ips = []
        for line in update_filter:
            if line:
                if line[0].isdigit():
                    # Jika baris dimulai dengan angka, itu kemungkinan adalah alamat IP
                    try:
                        # Coba parsing IP dengan modul ipaddress
                        ip = ipaddress.ip_network(line.strip().split('$')[0])
                        # Karakter setelah ip / akan di hilangkan + tanda ^
                        ips.append(str(ip).split('/')[0] + "^")
                    except ValueError:
                        # Jika parsing gagal, abaikan baris ini
                        pass
                else:
                    # Jika bukan alamat IP, itu kemungkinan adalah domain
                    domain = line.split("$")[0].strip()
                    if domain.startswith("*."):
                        domain_suffix = domain + "^"
                        domains.append("||" + domain_suffix)                       
                    elif domain.startswith("."):
                        domain_suffix = domain + "^"
                        domains.append("||*" + domain_suffix)
                    elif domain.endswith("."):
                        domain_suffix = domain + "*^"
                        domains.append("||" + domain_suffix)
                    elif domain.startswith("://"):
                        domain_suffix = domain + "^"
                        domains.append("||*." + domain_suffix)
                    elif any(prefix in domain for prefix in ("github", "pinterest", "pinimg")):
                        continue
                    else:
                        domains.append("||" + domain + "^")
        rules = domains + ["||" + ip for ip in ips]
        return rules
    except Exception as e:
        print(e)
        return None

update_rule_allAds = []
urls = [
        'https://adguardteam.github.io/HostlistsRegistry/assets/filter_22.txt',  #01 ABPindo
        'https://adguardteam.github.io/HostlistsRegistry/assets/filter_2.txt',   #02 AdAway
        'https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt',    #03 AdGuardDNS_filter
        'https://adguardteam.github.io/HostlistsRegistry/assets/filter_21.txt',  #04 CHN-antiAD
        'https://adguardteam.github.io/HostlistsRegistry/assets/filter_12.txt',  #05 Dandelion_AntiMalware
        'https://adguardteam.github.io/HostlistsRegistry/assets/filter_34.txt',  #06 HaGeZi_Personal
        'https://adguardteam.github.io/HostlistsRegistry/assets/filter_11.txt',  #07 Malicious_URLhaus
        'https://adguardteam.github.io/HostlistsRegistry/assets/filter_8.txt',   #08 NoCoin_filter
        'https://adguardteam.github.io/HostlistsRegistry/assets/filter_32.txt',  #09 NoTracking
        'https://adguardteam.github.io/HostlistsRegistry/assets/filter_27.txt',  #10 oisd_full
        'https://adguardteam.github.io/HostlistsRegistry/assets/filter_5.txt',   #11 oisd_small
        'https://adguardteam.github.io/HostlistsRegistry/assets/filter_30.txt',  #12 Phishing_URL
        'https://adguardteam.github.io/HostlistsRegistry/assets/filter_10.txt',  #13 Scam_byDurableNapkin
        'https://adguardteam.github.io/HostlistsRegistry/assets/filter_42.txt',  #14 ShadowWhisperer_Malware
        'https://adguardteam.github.io/HostlistsRegistry/assets/filter_31.txt',  #15 Stalkerware
        'https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-social-only/hosts',  #16 StevenBlackList
        'https://raw.githubusercontent.com/elliotwutingfeng/Inversion-DNSBL-Blocklists/main/Google_hostnames_ABP.txt' #17 Malicious
        'https://https://raw.githubusercontent.com/d3ward/toolz/master/src/d3host.txt' #18 d3ward
        'https://raw.githubusercontent.com/elliotwutingfeng/Inversion-DNSBL-Blocklists/main/Google_ipv4.txt'         #19 maliciousip
    ]
for url in urls:
    update_rule_allAds += get_rule_update(url)

# Parsing untuk menghapus baris duplikat, menulis 1 baris saja jika terdapat beberapa baris yang memiliki penulisan karakter sama persis, menghindari penulisan host domain & ip berualang
update_rule_allAds = list(set(update_rule_allAds))

output_dir = "AdG"
os.makedirs(output_dir, exist_ok=True)
output_path = os.path.join(output_dir, "rule_allAds.yaml")

if update_rule_allAds:
    with open("output_path", "w", encoding='utf-8') as f:
        f.write("\n".join(update_rule_allAds))
