import requests
import httpx
import socket
import json
import os
import random
import base64
import mmh3
import pyfiglet
from ipwhois import IPWhois
from colorama import Fore, Style, init
from datetime import datetime

init(autoreset=True)

class SubReconX:
    def __init__(self, domain):
        self.domain = domain
        self.subdomains = set()
        self.resolved = {}
        self.live_hosts = []
        self.output_dir = f"results_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(self.output_dir, exist_ok=True)

    def passive_enum_crtsh(self):
        print(f"{Fore.YELLOW}[+] Enumerating subdomains using crt.sh...{Style.RESET_ALL}")
        try:
            url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
            r = requests.get(url, timeout=15)
            if r.status_code == 200:
                data = r.json()
                for entry in data:
                    name = entry.get("name_value", "")
                    for sub in name.split("\n"):
                        sub = sub.strip()
                        if "*" not in sub and len(sub) <= 253:
                            self.subdomains.add(sub)
                print(f"{Fore.GREEN}[+] Found {len(self.subdomains)} unique subdomains.{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[-] crt.sh error: Status code {r.status_code}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[-] Error fetching from crt.sh: {e}{Style.RESET_ALL}")

    def resolve_subdomains(self):
        print(f"{Fore.YELLOW}[+] Resolving subdomains to IPs...{Style.RESET_ALL}")
        for sub in sorted(self.subdomains):
            try:
                ip = socket.gethostbyname(sub)
                self.resolved[sub] = ip
                print(f"{Fore.GREEN}[+] {sub} -> {ip}{Style.RESET_ALL}")
            except Exception:
                continue
        self._save("resolved.txt", [f"{k} -> {v}" for k, v in self.resolved.items()])

    def detect_live_hosts(self):
        print(f"{Fore.YELLOW}[+] Detecting live web applications using httpx...{Style.RESET_ALL}")
        try:
            client = httpx.Client(timeout=5, follow_redirects=True)
            for sub in self.resolved:
                url = f"http://{sub}"
                try:
                    r = client.get(url)
                    if r.status_code < 500:
                        headers = r.headers
                        title = self._extract_title(r.text)
                        info = {
                            "url": url,
                            "ip": self.resolved[sub],
                            "title": title or "N/A",
                            "content_length": headers.get("content-length", "N/A"),
                            "server": headers.get("server", "N/A"),
                            "cname": self._get_cname(sub),
                            "powered_by": headers.get("x-powered-by", "N/A"),
                            "tech_guess": self._guess_tech(r.text)
                        }
                        self.live_hosts.append(info)
                        print(f"{Fore.CYAN}[+] Live: {url} [{info['title']}]{Style.RESET_ALL}")
                except Exception:
                    continue
            client.close()
        except Exception as e:
            print(f"{Fore.RED}[-] Error initializing httpx: {e}{Style.RESET_ALL}")
        self._save_json("live_hosts.json", self.live_hosts)

    def check_subdomain_takeover(self):
        print(f"{Fore.YELLOW}[+] Checking for possible subdomain takeover...{Style.RESET_ALL}")
        signatures = ["There isn't a GitHub Pages site here", "NoSuchBucket", "herokucdn.com error", "The specified bucket does not exist"]
        candidates = []
        for sub, ip in self.resolved.items():
            try:
                r = httpx.get(f"http://{sub}", timeout=5)
                for sig in signatures:
                    if sig.lower() in r.text.lower():
                        print(f"{Fore.RED}[!] Possible Takeover: {sub} [{sig}]{Style.RESET_ALL}")
                        candidates.append({"subdomain": sub, "reason": sig})
            except:
                continue
        self._save_json("takeover_candidates.json", candidates)

    def enrich_with_asn(self):
        print(f"{Fore.YELLOW}[+] Enriching IPs with ASN and Geo info...{Style.RESET_ALL}")
        enriched = []
        for sub, ip in self.resolved.items():
            try:
                obj = IPWhois(ip)
                res = obj.lookup_rdap()
                enriched.append({
                    "subdomain": sub,
                    "ip": ip,
                    "asn": res.get("asn", "N/A"),
                    "isp": res.get("network", {}).get("name", "N/A"),
                    "country": res.get("network", {}).get("country", "N/A")
                })
            except:
                continue
        self._save_json("asn_geo.json", enriched)

    def scan_ports(self, top_ports=[80, 443, 22, 21, 8080, 3306, 25, 53]):
        print(f"{Fore.YELLOW}[+] Scanning top ports for live hosts...{Style.RESET_ALL}")
        port_data = []
        for host in self.resolved:
            open_ports = []
            for port in top_ports:
                try:
                    sock = socket.socket()
                    sock.settimeout(1)
                    sock.connect((host, port))
                    open_ports.append(port)
                    sock.close()
                except:
                    continue
            if open_ports:
                print(f"{Fore.GREEN}[+] {host} open ports: {open_ports}{Style.RESET_ALL}")
                port_data.append({"host": host, "open_ports": open_ports})
        self._save_json("open_ports.json", port_data)

    def fingerprint_favicon(self):
        print(f"{Fore.YELLOW}[+] Fingerprinting favicons...{Style.RESET_ALL}")
        hashes = []
        for info in self.live_hosts:
            try:
                r = httpx.get(info["url"] + "/favicon.ico", timeout=5)
                favicon = base64.encodebytes(r.content)
                hash_ = mmh3.hash(favicon)
                info["favicon_hash"] = hash_
                print(f"{Fore.CYAN}[+] {info['url']} favicon hash: {hash_}{Style.RESET_ALL}")
                hashes.append({"url": info["url"], "hash": hash_})
            except:
                continue
        self._save_json("favicon_hashes.json", hashes)

    def generate_html_report(self):
        print(f"{Fore.YELLOW}[+] Generating HTML report...{Style.RESET_ALL}")
        html_file = os.path.join(self.output_dir, "report.html")
        with open(html_file, "w") as f:
            f.write("<html><head><title>SubReconX Report</title></head><body>")
            f.write(f"<h1>Recon Report for {self.domain}</h1>")
            f.write("<h2>Live Hosts</h2><ul>")
            for host in self.live_hosts:
                f.write(f"<li>{host['url']} - {host['title']} - {host['server']}</li>")
            f.write("</ul></body></html>")
        print(f"{Fore.GREEN}[✔] HTML report saved to {html_file}{Style.RESET_ALL}")

    def _extract_title(self, html):
        try:
            start = html.lower().find("<title>")
            end = html.lower().find("</title>")
            if start != -1 and end != -1:
                return html[start+7:end].strip()
        except:
            pass
        return None

    def _get_cname(self, domain):
        try:
            return socket.gethostbyname_ex(domain)[0]
        except:
            return "N/A"

    def _guess_tech(self, html):
        tech = []
        if "wp-content" in html:
            tech.append("WordPress")
        if "jquery" in html:
            tech.append("jQuery")
        if "/static/" in html:
            tech.append("Django")
        if "react" in html.lower():
            tech.append("React")
        if not tech:
            return "Unknown"
        return ", ".join(tech)

    def _save(self, filename, lines):
        path = os.path.join(self.output_dir, filename)
        with open(path, "w") as f:
            for line in lines:
                f.write(line + "\n")

    def _save_json(self, filename, data):
        path = os.path.join(self.output_dir, filename)
        with open(path, "w") as f:
            json.dump(data, f, indent=2)

    def _log_secret_feature(self):
        secret_file = os.path.join(self.output_dir, ".secret_recon.log")
        with open(secret_file, "w") as f:
            f.write("SubReconX - Hidden Mode Active\n")
            f.write(f"{len(self.live_hosts)} live hosts found.\n")
            f.write(f"Scan ID: {random.randint(100000, 999999)}\n")

    def run(self):
        banner = pyfiglet.figlet_format("Qaisar-SubReconX")
        print(Fore.CYAN + banner + Style.RESET_ALL)

        self.passive_enum_crtsh()
        self.resolve_subdomains()
        self.detect_live_hosts()
        self.check_subdomain_takeover()
        self.enrich_with_asn()
        self.scan_ports()
        self.fingerprint_favicon()
        self.generate_html_report()
        self._log_secret_feature()
        print(f"{Fore.GREEN}[✔] Recon complete. Output saved in: {self.output_dir}{Style.RESET_ALL}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print(f"{Fore.RED}Usage: python3 sub_recon_x.py <domain.com>{Style.RESET_ALL}")
        exit(1)

    domain = sys.argv[1]
    recon = SubReconX(domain)
    recon.run()