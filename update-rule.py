import requests
import ipaddress
import yaml
import os

def get_update_rule(url):
    try:
        r = requests.get(url)
        update_rule = r.text.split("\n")
        update_rule = [line.replace("  - DOMAIN,", "").replace("  - DOMAIN-SUFFIX,", "").replace("  - IP-CIDR,", "").replace("||", "").replace("|", "").replace("://", "").replace("127.0.0.1 ", "").replace("0.0.0.0 ", "").replace("^", "") for line in update_rule if not line.startswith(('#', '!', '/', '@', '-', '&', 'payload:', '0.0.0.0 t.co'))]
        domains = []
        ips = []
        for line in update_rule:
            if line:
                if line[0].isdigit():
                    # Jika baris dimulai dengan angka, itu kemungkinan adalah alamat IP
                    try:
                        # Coba parsing IP dengan modul ipaddress
                        ip = ipaddress.ip_network(line.strip().split('$')[0])
                        ips.append(ip.with_prefixlen)
                    except ValueError:
                        # Jika parsing gagal, abaikan baris ini
                        pass
                else:
                    # Jika bukan alamat IP, itu kemungkinan adalah domain
                    domain = line.split("$")[0].strip()
                    if domain.endswith(".") and domain.startswith("*"):
                        domain_suffix = domain + "*"
                        domains.append("  - DOMAIN-SUFFIX," + domain_suffix)
                    elif domain.startswith("*"):
                        domain_suffix = domain + ""
                        domains.append("  - DOMAIN-SUFFIX," + domain_suffix) 
                    elif domain.endswith("."):
                        domain_suffix = domain + "*"
                        domains.append("  - DOMAIN-SUFFIX," + domain_suffix)                   
                    elif domain.startswith("."):
                        domain_suffix = domain + ""
                        domains.append("  - DOMAIN-SUFFIX,*" + domain_suffix)
                    elif domain.startswith("://"):
                        domain_suffix = domain + ""
                        domains.append("  - DOMAIN-SUFFIX,*." + domain_suffix)
           #         jika domain memiliki karakter "tiktok", "pinterest" dkk maka domain tersebut tidak akan ditambahkan
           #         elif any(prefix in domain for prefix in ("autodesk", "tiktok", "pinterest", "pinimg", "twitter", "twimg", "linkedin", "facebook", "fbcdn.net", "fbcdn.com", "fbcdn-a", "instagram", "whatsapp")):
           #             continue
                    else:
                        domains.append("  - DOMAIN," + domain)
        rules = domains + ["  - IP-CIDR," + ip for ip in ips]
        rules.insert(0, "payload:")
        return rules
    except Exception as e:
        print(e)
        return None


 # Write the filtered accounts to the YAML files with UTF-8 encoding
output_dir_1 = "backup/rule_provider"
output_path_1 = os.path.join(output_dir_1, "filter-liv.yaml")
output_path_2 = os.path.join(output_dir_1, "filter-XL.yaml")

    # Create the folders if they don't exist
os.makedirs(output_dir_1, exist_ok=True)


update_rule_ABPindo = get_update_rule("https://raw.githubusercontent.com/d3ward/toolz/master/src/d3host.txt")
if update_rule_ABPindo:
    with open(output_path_1, "w", encoding='utf-8') as file:
        file.write("\n".join(update_rule_ABPindo))

update_rule_AdAway = get_update_rule("https://raw.githubusercontent.com/rfxcll/v2ray-rules-dat/rule/rule_ads.txt")
if update_rule_AdAway:
    with open(output_path_2, "w", encoding='utf-8') as file:
        file.write("\n".join(update_rule_AdAway))

