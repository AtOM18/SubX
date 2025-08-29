import argparse
import csv
import json
import os
from concurrent.futures import ThreadPoolExecutor
import requests
from colorama import Fore, Style, init
from dotenv import load_dotenv  # Add this import


# Initialize colorama
init(autoreset=True)

# Load environment variables from .env file
load_dotenv()

banner = f"""
{Fore.CYAN},d88~~\\  888   |  888~~\\   Y88b    / 
{Fore.CYAN}8888     888   |  888   |   Y88b  /  
{Fore.CYAN}`Y88b    888   |  888 _/     Y88b/   
{Fore.CYAN} `Y88b,  888   |  888  \\     /Y88b   
{Fore.CYAN}   8888  Y88   |  888   |   /  Y88b  
{Fore.CYAN}\\__88P'   "8__/   888__/   /    Y88b   {Fore.YELLOW}v1.0
"""

# API keys (now loaded from .env)
shodan_api_key = os.getenv("SHODAN_API_KEY", "")
whoisxmlapi_api_key = os.getenv("WHOISXMLAPI_API_KEY", "")
certspotter_api_key = os.getenv("CERTSPOTTER_API_KEY", "")
dnsdb_api_key = os.getenv("DNSDB_API_KEY", "")
virustotal_api_key = os.getenv("VIRUSTOTAL_API_KEY", "")
recondev_api_key = os.getenv("RECONDEV_API_KEY", "")
passivetotal_api_key = os.getenv("PASSIVETOTAL_API_KEY", "")
passivetotal_api_secret = os.getenv("PASSIVETOTAL_API_SECRET", "")
censys_api_id = os.getenv("CENSYS_API_ID", "")
censys_api_secret = os.getenv("CENSYS_API_SECRET", "")
facebook_access_token = os.getenv("FACEBOOK_ACCESS_TOKEN", "")
binaryedge_api_key = os.getenv("BINARYEDGE_API_KEY", "")
spyse_api_key = os.getenv("SPYSE_API_KEY", "")

# Globals
domain = ""
subdomains = []

# Colored prefixes
success = f"[{Fore.GREEN}✓{Style.RESET_ALL}] "
info    = f"[{Fore.YELLOW}‣{Style.RESET_ALL}] "
fail    = f"[{Fore.RED}×{Style.RESET_ALL}] "


# ---------------------- Data Gathering Functions ---------------------- #
def certspotter():
    print(info + "Gathering data from Cert Spotter…")
    headers = {"Authorization": f"Bearer {certspotter_api_key}"}
    response = requests.get(f"https://api.certspotter.com/v1/issuances?domain={domain}&expand=dns_names",
                            headers=headers, stream=True)
    try:
        data = response.json()
        for dns_names in data:
            for dns_name in dns_names["dns_names"]:
                if not dns_name.startswith('*') and dns_name not in subdomains:
                    subdomains.append(dns_name)
    except:
        pass


def hackertarget():
    print(info + "Gathering data from Hacker Target…")
    response = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", stream=True)
    lines = response.text.split("\n")
    for line in lines:
        sub = line.split(",")[0]
        if sub and sub not in subdomains:
            subdomains.append(sub)


def shodan():
    print(info + "Gathering data from Shodan…")
    response = requests.get(f"https://api.shodan.io/dns/domain/{domain}?key={shodan_api_key}", stream=True)
    try:
        data = response.json()
        for sub in data["subdomains"]:
            if sub + "." + domain not in subdomains:
                subdomains.append(sub + "." + domain)
    except:
        pass


def omnisint():
    print(info + "Gathering data from Omnisint…")
    response = requests.get(f"https://sonar.omnisint.io/subdomains/{domain}", stream=True)
    try:
        data = response.json()
        for sub in data:
            if sub not in subdomains:
                subdomains.append(sub)
    except:
        pass


def dns_bufferover():
    print(info + "Gathering data from DNS Bufferover…")
    response = requests.get(f"https://dns.bufferover.run/dns?q=.{domain}", stream=True)
    try:
        data = response.json()
        for line in data.get("FDNS_A", []):
            sub = line.split(",")[1]
            if sub not in subdomains:
                subdomains.append(sub)
    except:
        pass


def tls_bufferover():
    print(info + "Gathering data from TLS Bufferover…")
    response = requests.get(f"https://tls.bufferover.run/dns?q=.{domain}", stream=True)
    try:
        data = response.json()
        for line in data.get("Results", []):
            sub = line.split(",")[2]
            if not sub.startswith('*') and sub not in subdomains:
                subdomains.append(sub)
    except:
        pass


def sublist3r():
    print(info + "Gathering data from Sublist3r…")
    response = requests.get(f"https://api.sublist3r.com/search.php?domain={domain}", stream=True)
    try:
        data = response.json()
        for sub in data:
            if sub not in subdomains:
                subdomains.append(sub)
    except:
        pass


def threatcrowd():
    print(info + "Gathering data from Threat Crowd…")
    response = requests.get(f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}", stream=True)
    try:
        data = response.json()
        for sub in data.get("subdomains", []):
            if sub not in subdomains:
                subdomains.append(sub)
    except:
        pass


def threatminer():
    print(info + "Gathering data from Threat Miner…")
    response = requests.get(f"https://api.threatminer.org/v2/domain.php?q={domain}&rt=5", stream=True)
    try:
        data = response.json()
        for sub in data.get("results", []):
            if sub not in subdomains:
                subdomains.append(sub)
    except:
        pass


def virustotal():
    print(info + "Gathering data from VirusTotal…")
    headers = {"x-apikey": virustotal_api_key}
    response = requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains",
                            headers=headers, stream=True)
    try:
        data = response.json()
        for sub in data.get("data", []):
            if sub["id"] not in subdomains:
                subdomains.append(sub["id"])
    except:
        pass


def securitytrails():
    print(info + "Gathering data from SecurityTrails…")
    headers = {"apikey": "ITTUAQ0A0v4yzSbClTTySceSjPbwswsC"}
    response = requests.get(f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
                            headers=headers, stream=True)
    try:
        data = response.json()
        for sub in data.get("subdomains", []):
            if sub + "." + domain not in subdomains:
                subdomains.append(sub + "." + domain)
    except:
        pass


def alienvault():
    print(info + "Gathering data from AlienVault…")
    response = requests.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns", stream=True)
    try:
        data = response.json()
        for sub in data.get("passive_dns", []):
            if sub["hostname"] not in subdomains:
                subdomains.append(sub["hostname"])
    except:
        pass


def urlscan():
    print(info + "Gathering data from Urlscan…")
    response = requests.get(f"https://urlscan.io/api/v1/search/?q=domain:{domain}", stream=True)
    try:
        data = response.json()
        for res in data.get("results", []):
            if res["page"]["domain"] not in subdomains:
                subdomains.append(res["page"]["domain"])
    except:
        pass


def crt():
    print(info + "Gathering data from Crt.sh…")
    response = requests.get(f"https://crt.sh/?q={domain}&output=json", stream=True)
    try:
        data = response.json()
        for res in data:
            for sub in res["name_value"].split("\n"):
                if not sub.startswith('*') and sub not in subdomains:
                    subdomains.append(sub)
    except:
        pass


def anubis():
    print(info + "Gathering data from Anubis…")
    response = requests.get(f"https://jldc.me/anubis/subdomains/{domain}", stream=True)
    try:
        data = response.json()
        for sub in data:
            if sub not in subdomains:
                subdomains.append(sub)
    except:
        pass


def dnsdb():
    print(info + "Gathering data from DNSdb…")
    headers = {"Accept": "application/json", "Content-Type": "application/json", "X-API-Key": dnsdb_api_key}
    response = requests.get(f"https://api.dnsdb.info/lookup/rrset/name/*.{domain}?limit=1000000000",
                            headers=headers, stream=True)
    try:
        for line in response.text.split("\n"):
            if line.strip() == "":
                continue
            sub = json.loads(line)["rrname"].rstrip(".")
            if "_" not in sub and sub not in subdomains:
                subdomains.append(sub)
    except:
        pass


def recondev():
    print(info + "Gathering data from Recon.dev…")
    response = requests.get(f"https://recon.dev/api/search?key={recondev_api_key}&domain={domain}", stream=True)
    try:
        data = response.json()
        for res in data:
            for sub in res["rawDomains"]:
                if not sub.startswith('*') and "." + domain in sub and sub not in subdomains:
                    subdomains.append(sub)
    except:
        pass


def passivetotal():
    print(info + "Gathering data from PassiveTotal…")
    auth = (passivetotal_api_key, passivetotal_api_secret)
    response = requests.get(f"https://api.passivetotal.org/v2/enrichment/subdomains?query={domain}",
                            auth=auth, stream=True)
    try:
        data = response.json()
        for sub in data.get("subdomains", []):
            if sub + "." + domain not in subdomains:
                subdomains.append(sub + "." + domain)
    except:
        pass


def censys():
    print(info + "Gathering data from Censys…")
    page = pages = 1
    while page <= pages:
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        auth = (censys_api_id, censys_api_secret)
        data = {"query": domain, "page": page, "fields": ["parsed.names"]}
        response = requests.post("https://www.censys.io/api/v1/search/certificates",
                                 headers=headers, json=data, auth=auth, stream=True)
        try:
            data = response.json()
            pages = data["metadata"]["pages"]
            for res in data["results"]:
                for sub in res["parsed.names"]:
                    sub = sub.replace("http://", "").replace("https://", "")
                    if "." + domain in sub and not sub.startswith("*") and sub not in subdomains:
                        subdomains.append(sub)
        except:
            break
        page += 1


def riddler():
    print(info + "Gathering data from Riddler…")
    response = requests.get(f"https://riddler.io/search/exportcsv?q=pld:{domain}", stream=True)
    data = csv.reader(line.decode('utf-8') for line in response.iter_lines())
    try:
        next(data)
        next(data)
        for row in data:
            if row[4] not in subdomains:
                subdomains.append(row[4])
    except:
        pass


def facebook():
    print(info + "Gathering data from Facebook…")
    response = requests.get(
        f"https://graph.facebook.com/certificates?query={domain}&fields=domains&limit=10000&access_token={facebook_access_token}",
        stream=True)
    try:
        data = response.json()
        for res in data.get("data", []):
            for sub in res["domains"]:
                if not sub.startswith('*') and sub not in subdomains:
                    subdomains.append(sub)
    except:
        pass


def binaryedge():
    print(info + "Gathering data from BinaryEdge…")
    page = pages = 1
    while page <= pages:
        headers = {"X-Key": binaryedge_api_key}
        response = requests.get(f"https://api.binaryedge.io/v2/query/domains/subdomain/{domain}?page={page}",
                                headers=headers, stream=True)
        try:
            data = response.json()
            pages = data["pagesize"]
            for sub in data.get("events", []):
                if sub not in subdomains:
                    subdomains.append(sub)
        except:
            break
        page += 1


# ---------------------- Orchestration ---------------------- #
def enum(arguments):
    print(Fore.GREEN + "[*] Please, wait. Processing data..." + Style.RESET_ALL)

    with ThreadPoolExecutor(max_workers=20) as executor:
        try:
            executor.submit(certspotter)
            executor.submit(shodan)
            executor.submit(omnisint)
            executor.submit(hackertarget)
            executor.submit(dns_bufferover)
            executor.submit(tls_bufferover)
            executor.submit(sublist3r)
            executor.submit(virustotal)
            executor.submit(threatcrowd)
            executor.submit(securitytrails)
            executor.submit(threatminer)
            executor.submit(alienvault)
            executor.submit(urlscan)
            executor.submit(crt)
            executor.submit(anubis)
            executor.submit(dnsdb)
            executor.submit(recondev)
            executor.submit(censys)
            executor.submit(riddler)
            executor.submit(facebook)
            executor.submit(binaryedge)
            # WIP: executor.submit(whoisxmlapi)
            # WIP: executor.submit(spyse)

            executor.shutdown(wait=True)
        except KeyboardInterrupt:
            executor.shutdown()
            print("\n" + success + "Goodbye, friend!")
            exit(0)

    # remove TLD itself
    if domain in subdomains:
        subdomains.remove(domain)

    if arguments.output:
        print("\n" + success + "Saving " + str(len(subdomains)) + " subdomains to " + arguments.output + "!")
        with open(arguments.output, 'w') as file:
            for sub in subdomains:
                file.write(sub + "\n")
    else:
        print("\n" + success + "Found " + str(len(subdomains)) + " subdomains:")
        for sub in subdomains:
            print(sub)


def args():
    parser = argparse.ArgumentParser(usage="python3 subzero.py [domain]",
                                     description="Passive subdomain enumeration tool for bug-bounty hunters & penetration testers.")
    parser.add_argument('-v', '--version', action='version', version='%(prog)s 1.0')
    parser.add_argument('domain', metavar='[domain]', action='store', help='specifies the target domain')
    parser.add_argument("-o", "--output", action="store", dest="output", help="Specifies the output file.")
    return parser.parse_args()


# ---------------------- Main ---------------------- #
if __name__ == "__main__":
    print(banner)
    domain = args().domain
    print(success + "Target domain: " + Fore.GREEN + domain + Style.RESET_ALL + "\n")
    enum(args())
