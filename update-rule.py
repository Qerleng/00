import requests
import ipaddress
import yaml
import os

def get_update_rule(url):
    try:
        r = requests.get(url)
        update_rule = r.text.split("\n")
        update_rule = [line.replace("- DST-PORT,", "").replace("  - DOMAIN-SUFFIX,", "").replace("  - IP-CIDR,", "").replace("||", "").replace("|", "").replace("://", "").replace("127.0.0.1 ", "").replace("0.0.0.0 ", "").replace("^", "") for line in update_rule if not line.startswith(('#', '!', '/', '@', '-', '&', 'payload:', '0.0.0.0 t.co'))]
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



update_rule_ABPindo = get_update_rule("https://raw.githubusercontent.com/Qerleng/Klompig/main/rule_provider/TEST.yaml")
if update_rule_ABPindo:
    with open("rule_ABPindo.yaml", "w", encoding='utf-8') as f:
        f.write("\n".join(update_rule_ABPindo))


