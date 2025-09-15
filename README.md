# SubX

**Passive subdomain enumeration + live-probing + screenshotting + visualization**
A pragmatic tool for bug-bounty hunters and penetration testers. SubX collects passive subdomain data from public APIs, probes which hosts are live, captures headless Chromium screenshots, computes perceptual hashes, and visualizes clusters with `pyvis`.

---

## Features

* Passive subdomain enumeration using multiple public APIs (aggregates results).
* HTTP probe to determine **live** hosts (HTTP/HTTPS).
* Headless Chromium screenshots for live hosts.
* pHash-based image similarity (`ImageHash`).
* Interactive graph visualization (pyvis) using clustering signals:

  * subdomain name similarity
  * HTTP response code
  * image similarity (pHash Hamming distance)
  * HTML title similarity
* CSV-based single source of truth for all runs and metadata.
* Concurrent requests with configurable thread count and timeout.

---

## Requirements

`requirements.txt` should contain:

```
requests
colorama
python-dotenv
httpx
pandas
networkx
pyvis
Pillow
ImageHash
```

Additional requirements:

* Python 3.8+ recommended.
* Chromium / Google Chrome must be installed and available in PATH for headless screenshots.

Install:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

## Quick usage

```
usage: python3 subx.py [options] [domain]

Passive subdomain enumeration tool for bug-bounty hunters & penetration testers.
```


### Modes

* `0` — Subdomain enumeration only (default).
* `1` — Enumeration + live HTTP probe.
* `2` — Screenshots generation for live domains (reads live hosts from CSV).
* `3` — Visualize clusters (generate interactive `pyvis` HTML graph).

### Examples

* Passive enumeration:

```bash
python3 subx.py -m 0 example.com
```

* Enumeration + probe, 50 threads, 8s timeout:

```bash
python3 subx.py -m 1 -t 50 --timeout 8 example.com
```

* Generate screenshots from CSV:

```bash
python3 subx.py -m 2 -o results_screenshots.csv example.com
```

* Build interactive graph HTML:

```bash
python3 subx.py -m 3 -o results_graph.csv example.com
```

---

---
## Disclaimer

This tool is only for testing and academic purposes and can only be used where strict consent has been given. Do not use it for illegal purposes! It is the end user’s responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this tool and software.

---
## License

This project is licensed under the GPLv3 License - see the [LICENSE](https://github.com/AtOM18/SubX/blob/main/LICENSE) file for details

---

