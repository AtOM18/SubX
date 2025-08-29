import os
import requests
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style

# API keys from environment variables
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

success = f"[{Fore.GREEN}✓{Style.RESET_ALL}] "
info    = f"[{Fore.YELLOW}‣{Style.RESET_ALL}] "
fail    = f"[{Fore.RED}×{Style.RESET_ALL}] "

def safe_call(func):
    def wrapper(domain, subdomains, errors=None):
        try:
            func(domain, subdomains)
        except Exception as e:
            msg = f"[{func.__name__}] failed: {e}"
            if errors is not None:
                errors.append(msg)
    return wrapper

@safe_call
def certspotter(domain, subdomains):
    print(info + "Gathering data from Cert Spotter…")
    headers = {"Authorization": f"Bearer {certspotter_api_key}"}
    response = requests.get(f"https://api.certspotter.com/v1/issuances?domain={domain}&expand=dns_names",
                            headers=headers, stream=True)
    data = response.json()
    for dns_names in data:
        for dns_name in dns_names["dns_names"]:
            if not dns_name.startswith('*') and dns_name not in subdomains:
                subdomains.append(dns_name)

@safe_call
def hackertarget(domain, subdomains):
    print(info + "Gathering data from Hacker Target…")
    response = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", stream=True)
    lines = response.text.split("\n")
    for line in lines:
        sub = line.split(",")[0]
        if sub and sub not in subdomains:
            subdomains.append(sub)

@safe_call
def shodan(domain, subdomains):
    print(info + "Gathering data from Shodan…")
    response = requests.get(f"https://api.shodan.io/dns/domain/{domain}?key={shodan_api_key}", stream=True)
    data = response.json()
    for sub in data.get("subdomains", []):
        fqdn = sub + "." + domain
        if fqdn not in subdomains:
            subdomains.append(fqdn)

@safe_call
def omnisint(domain, subdomains):
    print(info + "Gathering data from Omnisint…")
    response = requests.get(f"https://sonar.omnisint.io/subdomains/{domain}", stream=True)
    data = response.json()
    for sub in data:
        if sub not in subdomains:
            subdomains.append(sub)

@safe_call
def dns_bufferover(domain, subdomains):
    print(info + "Gathering data from DNS Bufferover…")
    response = requests.get(f"https://dns.bufferover.run/dns?q=.{domain}", stream=True)
    data = response.json()
    for line in data.get("FDNS_A", []):
        sub = line.split(",")[1]
        if sub not in subdomains:
            subdomains.append(sub)

@safe_call
def tls_bufferover(domain, subdomains):
    print(info + "Gathering data from TLS Bufferover…")
    response = requests.get(f"https://tls.bufferover.run/dns?q=.{domain}", stream=True)
    data = response.json()
    for line in data.get("Results", []):
        sub = line.split(",")[2]
        if not sub.startswith('*') and sub not in subdomains:
            subdomains.append(sub)

@safe_call
def sublist3r(domain, subdomains):
    print(info + "Gathering data from Sublist3r…")
    response = requests.get(f"https://api.sublist3r.com/search.php?domain={domain}", stream=True)
    data = response.json()
    for sub in data:
        if sub not in subdomains:
            subdomains.append(sub)

@safe_call
def threatcrowd(domain, subdomains):
    print(info + "Gathering data from Threat Crowd…")
    response = requests.get(f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}", stream=True)
    data = response.json()
    for sub in data.get("subdomains", []):
        if sub not in subdomains:
            subdomains.append(sub)

@safe_call
def threatminer(domain, subdomains):
    print(info + "Gathering data from Threat Miner…")
    response = requests.get(f"https://api.threatminer.org/v2/domain.php?q={domain}&rt=5", stream=True)
    data = response.json()
    for sub in data.get("results", []):
        if sub not in subdomains:
            subdomains.append(sub)

@safe_call
def virustotal(domain, subdomains):
    print(info + "Gathering data from VirusTotal…")
    headers = {"x-apikey": virustotal_api_key}
    response = requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains",
                            headers=headers, stream=True)
    data = response.json()
    for sub in data.get("data", []):
        if sub["id"] not in subdomains:
            subdomains.append(sub["id"])

@safe_call
def securitytrails(domain, subdomains):
    print(info + "Gathering data from SecurityTrails…")
    headers = {"apikey": "ITTUAQ0A0v4yzSbClTTySceSjPbwswsC"}
    response = requests.get(f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
                            headers=headers, stream=True)
    data = response.json()
    for sub in data.get("subdomains", []):
        fqdn = sub + "." + domain
        if fqdn not in subdomains:
            subdomains.append(fqdn)

@safe_call
def alienvault(domain, subdomains):
    print(info + "Gathering data from AlienVault…")
    response = requests.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns", stream=True)
    data = response.json()
    for sub in data.get("passive_dns", []):
        if sub["hostname"] not in subdomains:
            subdomains.append(sub["hostname"])

@safe_call
def urlscan(domain, subdomains):
    print(info + "Gathering data from Urlscan…")
    response = requests.get(f"https://urlscan.io/api/v1/search/?q=domain:{domain}", stream=True)
    data = response.json()
    for res in data.get("results", []):
        if res["page"]["domain"] not in subdomains:
            subdomains.append(res["page"]["domain"])

@safe_call
def crt(domain, subdomains):
    print(info + "Gathering data from Crt.sh…")
    response = requests.get(f"https://crt.sh/?q={domain}&output=json", stream=True)
    data = response.json()
    for res in data:
        for sub in res["name_value"].split("\n"):
            if not sub.startswith('*') and sub not in subdomains:
                subdomains.append(sub)

@safe_call
def anubis(domain, subdomains):
    print(info + "Gathering data from Anubis…")
    response = requests.get(f"https://jldc.me/anubis/subdomains/{domain}", stream=True)
    data = response.json()
    for sub in data:
        if sub not in subdomains:
            subdomains.append(sub)

@safe_call
def dnsdb(domain, subdomains):
    print(info + "Gathering data from DNSdb…")
    headers = {"Accept": "application/json", "Content-Type": "application/json", "X-API-Key": dnsdb_api_key}
    response = requests.get(f"https://api.dnsdb.info/lookup/rrset/name/*.{domain}?limit=1000000000",
                            headers=headers, stream=True)
    for line in response.text.split("\n"):
        if line.strip() == "":
            continue
        import json as _json
        sub = _json.loads(line)["rrname"].rstrip(".")
        if "_" not in sub and sub not in subdomains:
            subdomains.append(sub)

@safe_call
def recondev(domain, subdomains):
    print(info + "Gathering data from Recon.dev…")
    response = requests.get(f"https://recon.dev/api/search?key={recondev_api_key}&domain={domain}", stream=True)
    data = response.json()
    for res in data:
        for sub in res["rawDomains"]:
            if not sub.startswith('*') and "." + domain in sub and sub not in subdomains:
                subdomains.append(sub)

@safe_call
def passivetotal(domain, subdomains):
    print(info + "Gathering data from PassiveTotal…")
    auth = (passivetotal_api_key, passivetotal_api_secret)
    response = requests.get(f"https://api.passivetotal.org/v2/enrichment/subdomains?query={domain}",
                            auth=auth, stream=True)
    data = response.json()
    for sub in data.get("subdomains", []):
        fqdn = sub + "." + domain
        if fqdn not in subdomains:
            subdomains.append(fqdn)

@safe_call
def censys(domain, subdomains):
    print(info + "Gathering data from Censys…")
    page = pages = 1
    while page <= pages:
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        auth = (censys_api_id, censys_api_secret)
        data = {"query": domain, "page": page, "fields": ["parsed.names"]}
        response = requests.post("https://www.censys.io/api/v1/search/certificates",
                                 headers=headers, json=data, auth=auth, stream=True)
        data = response.json()
        pages = data["metadata"]["pages"]
        for res in data["results"]:
            for sub in res["parsed.names"]:
                sub = sub.replace("http://", "").replace("https://", "")
                if "." + domain in sub and not sub.startswith("*") and sub not in subdomains:
                    subdomains.append(sub)
        page += 1

@safe_call
def riddler(domain, subdomains):
    print(info + "Gathering data from Riddler…")
    import csv
    response = requests.get(f"https://riddler.io/search/exportcsv?q=pld:{domain}", stream=True)
    data = csv.reader(line.decode('utf-8') for line in response.iter_lines())
    next(data)
    next(data)
    for row in data:
        if row[4] not in subdomains:
            subdomains.append(row[4])

@safe_call
def facebook(domain, subdomains):
    print(info + "Gathering data from Facebook…")
    response = requests.get(
        f"https://graph.facebook.com/certificates?query={domain}&fields=domains&limit=10000&access_token={facebook_access_token}",
        stream=True)
    data = response.json()
    for res in data.get("data", []):
        for sub in res["domains"]:
            if not sub.startswith('*') and sub not in subdomains:
                subdomains.append(sub)

@safe_call
def binaryedge(domain, subdomains):
    print(info + "Gathering data from BinaryEdge…")
    page = pages = 1
    while page <= pages:
        headers = {"X-Key": binaryedge_api_key}
        response = requests.get(f"https://api.binaryedge.io/v2/query/domains/subdomain/{domain}?page={page}",
                                headers=headers, stream=True)
        data = response.json()
        pages = data.get("pagesize", 1)
        for sub in data.get("events", []):
            if sub not in subdomains:
                subdomains.append(sub)
        page += 1

def enum(domain, output=None):
    subdomains = []
    print(Fore.GREEN + "[*] Please, wait. Processing data..." + Style.RESET_ALL)

    functions = [
        certspotter,
        shodan,
        omnisint,
        hackertarget,
        dns_bufferover,
        tls_bufferover,
        sublist3r,
        virustotal,
        threatcrowd,
        securitytrails,
        threatminer,
        alienvault,
        urlscan,
        crt,
        anubis,
        dnsdb,
        recondev,
        censys,
        riddler,
        facebook,
        binaryedge,
    ]

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(func, domain, subdomains) for func in functions]
        try:
            for future in futures:
                future.result()
        except KeyboardInterrupt:
            executor.shutdown()
            print("\n" + success + "Goodbye, friend!")
            exit(0)

    # remove TLD itself
    if domain in subdomains:
        subdomains.remove(domain)

    if output:
        print("\n" + success + f"Saving {len(subdomains)} subdomains to {output}!")
        with open(output, 'w') as file:
            for sub in subdomains:
                file.write(sub + "\n")
    else:
        for sub in subdomains:
            print(sub)
        print("\n" + success + f"Found {len(subdomains)} subdomains:")

    return subdomains