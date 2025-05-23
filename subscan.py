import requests
import argparse
import ipaddress
import socket
import sys
import time
import pandas as pd
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed

parser = argparse.ArgumentParser(description="find Subdomain and get IP Address v0.3")
parser.add_argument("-f", "--file", help="domain list file")
parser.add_argument("-d", "--domain", help="single domain")
parser.add_argument("-o", "--outfile", help="output file name")
parser.add_argument("-w", "--wordlist", help="wordlist for brute-forcing subdomains")
parser.add_argument("--brute", help="brute mode", action="store_true")
parser.add_argument("--print", help="print mode", action="store_true")
parser.add_argument("--recurse", help="recurse mode", action="store_true")
parser.add_argument("--threads", type=int, default=10, help="set maximum number of worker threads (default: 10)")
parser.add_argument("--delay", type=int, default=1, help="set delay (seconds) between crt.sh queries (default: 1)")
parser.add_argument("--timeout", type=int, default=20, help="set HTTP request timeout to crt.sh in seconds (default: 20)")
parser.add_argument("--dns-timeout", type=int, default=5, help="set DNS query timeout in seconds (default: 5)")

args = parser.parse_args()

def printBanner():
    print("""
 _____         _                              
/  ___|       | |                             
\ `--.  _   _ | |__   ___   ___   __ _  _ __  
 `--. \| | | || '_ \ / __| / __| / _` || '_ \ 
/\__/ /| |_| || |_) |\__ \| (__ | (_| || | | |
\____/  \__,_||_.__/ |___/ \___| \__,_||_| |_|
                                              
    Subdomain & IP Address scanner v0.3
    Copyright 2025. Mick3y                                

""")

def resolveSubdomain(subdomain, timeout):
    try:
        answers = dns.resolver.resolve(subdomain, 'A', lifetime=timeout)
        ips = [rdata.to_text() for rdata in answers]
        return subdomain, ips
    except Exception:
        return None

def loadWordlist(path):
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        return [line.strip() for line in f if line.strip()]

def getSubdomainFromCrt(domain):
    url = f"https://crt.sh/?q={domain}&output=json"
    try:
        resp = requests.get(url, timeout=args.timeout)
        resp.raise_for_status()
    except requests.exceptions.Timeout:
        print(f"[-] Request to crt.sh timed out for domain: {domain}")
        return []
    except requests.exceptions.RequestException as e:
        print(f"[-] Request to crt.sh failed for domain {domain}: {e}")
        return []

    try:
        data = resp.json()
    except ValueError:
        print(f"[-] Invalid JSON returned from crt.sh for domain: {domain}")
        return []
    names = set()
    for entry in data:
        cn = entry.get('common_name')
        if not cn:
            continue
        for name in cn.splitlines():
            clean = name.strip().lower().lstrip("*.")
            if clean.endswith(domain):
                names.add(clean)

    for sb in sorted(names):
        print(f"  - {sb}")
    return sorted(names)


def getSubdomainFromBruteForcing(wordlist, domains):
    candidates = [f"{w}.{d}" for d in domains for w in wordlist]
    total = len(candidates)
    found = []

    print(f"""
            
────────────────────────────────────────────────────────────────────────────────────────
    [*] Starting brute-forcing {total} candidates using {args.threads} threads
────────────────────────────────────────────────────────────────────────────────────────
            
    """)
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {
            executor.submit(resolveSubdomain, sub, args.dns_timeout): sub
            for sub in candidates
        }
        for i, future in enumerate(as_completed(futures), 1):
            sub = futures[future]
            sys.stdout.write(f"\r[{i:4}/{total}] Trying: {sub}\033[K")
            sys.stdout.flush()

            result = future.result()
            if result:
                subdomain, ips = result
                found.append((subdomain, ips))
    print()
    return found

def checkOptions():
    if not (args.file or args.domain):
        print("[-] Please specify either '-f' or '-d' to search for subdomains. See README.md for details.")
        exit()
    if args.file and args.domain:
        print("[-] Please use only one of '-f' or '-d', not both.")
        exit()
    if not (args.outfile or args.print):
        print("[-] Please specify either '-o' to save results or '--print' to display them.")
        exit()
    if not args.brute:
        if args.recurse:
            print("[-] '--recurse' can only be used with '--brute'.")
            exit()
        elif args.wordlist:
            print("[-] '--wordlist' can only be used with '--brute'.")
            exit()               
    if args.brute and not args.wordlist:
        print("[-] Brute-force mode requires specifying '-w/--wordlist'.")
        exit()

def getDomains(path):
    with open(path, 'r') as f:
        return [line.strip() for line in f if line.strip()]

def convertDomainToAddress(domain):
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None

def getCloudPrefixes():
    aws = requests.get("https://ip-ranges.amazonaws.com/ip-ranges.json").json()['prefixes']
    gcp = requests.get("https://www.gstatic.com/ipranges/cloud.json").json()['prefixes']
    return aws, gcp

def checkIsCloud(ip, aws_prefixes, gcp_prefixes):
    if not ip:
        return "Unresolved"
    addr = ipaddress.ip_address(ip)
    for p in aws_prefixes:
        if addr in ipaddress.ip_network(p['ip_prefix']):
            return f"Amazon Web Service"
    for p in gcp_prefixes:
        if 'ipv4Prefix' in p and addr in ipaddress.ip_network(p['ipv4Prefix']):
            return f"Google Cloud Platform"
    return ""

def putResults(domains, awsPrifixes, gcpPrifixes):
    rows = []
    for dom in domains:
        ip    = convertDomainToAddress(dom)
        cloud = checkIsCloud(ip, awsPrifixes, gcpPrifixes)
        rows.append({
            "도메인": dom,
            "IP":      ip or " ",
            "비고":    cloud
        })
    df = pd.DataFrame(rows)
    if not (args.outfile or args.print):
        print("[-] You have to use a flag either '-o' or '-p' for saving or seeing results.")
        exit()
    if args.print:
        print(df.to_string(index=False))
    if args.outfile:
        ext = args.outfile.lower()
        if ext.endswith('.xlsx'):
            df.to_excel(args.outfile, index=False)
        elif ext.endswith('.txt'):
            df.to_csv(args.outfile, sep='\t', index=False)
        else:
            print("[-] output file extension must be '.xlsx' or '.txt'")
            exit()

def printFooter():
    print("""
          
────────────────────────────────────────────────────────────────────────────────────────
    [+] This tool just completed the subdomain enumeration and IP address resolution 
────────────────────────────────────────────────────────────────────────────────────────
          
""")

def main():
    printBanner()
    checkOptions()

    if args.domain:
        base = [args.domain]
    else:
        base = getDomains(args.file)

    all_subs = []
    for d in base:
        print(f"""
            
────────────────────────────────────────────────────────────────────────────────────────
    [*] Querying crt.sh for {d}
────────────────────────────────────────────────────────────────────────────────────────
            
        """)
        time.sleep(args.delay)
        subs = getSubdomainFromCrt(d)
        all_subs.extend(subs)
    all_subs = list(dict.fromkeys(all_subs))

    if args.brute:
        if not args.recurse:
            bruted = getSubdomainFromBruteForcing(loadWordlist(args.wordlist), base)
            all_subs = list(dict.fromkeys(all_subs + [s for s, _ in bruted]))
        
        elif args.recurse:
            bruted2 = getSubdomainFromBruteForcing(loadWordlist(args.wordlist), all_subs)
            all_subs = list(dict.fromkeys(all_subs + [s for s, _ in bruted2]))

    aws_pref, gcp_pref = getCloudPrefixes()
    printFooter()
    putResults(all_subs, aws_pref, gcp_pref)

    print("[+] Done.")

if __name__ == "__main__":
    main()
