import asyncio
import httpx
import csv
import os
from colorama import Fore, Style

success = f"[{Fore.GREEN}✓{Style.RESET_ALL}] "

async def probe_subdomain(subdomain, timeout):
    ports = [80, 443]
    for port in ports:
        scheme = "https" if port == 443 else "http"
        url = f"{scheme}://{subdomain}"
        try:
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, verify=False) as client:
                resp = await client.get(url)
                title = ""
                if resp.status_code and resp.text:
                    import re
                    m = re.search(r"<title>(.*?)</title>", resp.text, re.IGNORECASE | re.DOTALL)
                    if m:
                        title = m.group(1).strip()
                return (subdomain, resp.status_code, title, port, scheme)
        except Exception:
            continue
    return (subdomain, "No response", "", "", "")

async def probe_all(subdomains, timeout, threads, progress_callback=None):
    tasks = []
    sem = asyncio.Semaphore(threads)
    progress = {"checked": 0}

    async def sem_probe(subdomain):
        async with sem:
            result = await probe_subdomain(subdomain, timeout)
            progress["checked"] += 1
            if progress_callback:
                progress_callback(progress["checked"], len(subdomains))
            return result

    for sub in subdomains:
        tasks.append(sem_probe(sub))
    return await asyncio.gather(*tasks)

def probe_mode(domain, output, verbose, threads, timeout, enum_func):
    print(success + "Target domain: " + Fore.GREEN + domain + Style.RESET_ALL + "\n")
    # Step 1: Get subdomains
    subdomains = []
    if output:
        enum_func(domain, output, verbose, threads, timeout)
        with open(output, "r") as f:
            subdomains = [line.strip() for line in f if line.strip()]
    else:
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False, mode="w+", encoding="utf-8") as tmpf:
            enum_func(domain, tmpf.name, verbose, threads, timeout)
            tmpf.seek(0)
            subdomains = [line.strip() for line in tmpf if line.strip()]
    print(success + f"Probing {len(subdomains)} subdomains for HTTP/HTTPS...\n")

    # Step 2: Probe subdomains with live progress bar
    checked = [0]
    total = len(subdomains)

    def progress_callback(done, total):
        percent = (done / total) * 100 if total else 0
        print(f"\rProbed: {done}/{total} ({percent:.2f}%)", end='', flush=True)

    results = asyncio.run(probe_all(subdomains, timeout, threads, progress_callback=progress_callback))
    print(f"\n{success}Probing complete: {total}/{total} subdomains checked.")

    # Step 3: Write results to CSV with alive/not_alive flag
    csv_file = f"{output}.csv" if output else f"{domain}_probed.csv"
    live_hosts = 0
    with open(csv_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["subdomain", "response_code", "title", "port", "scheme", "status"])
        for row in results:
            # Determine alive status
            is_alive = isinstance(row[1], int) and 200 <= row[1] < 500
            status = "alive" if is_alive else "not_alive"
            writer.writerow(list(row) + [status])
            if is_alive:
                live_hosts += 1
    print(success + f"Results written to {csv_file}")
    print(success + f"Total live hosts: {live_hosts} out of {total} subdomains.")