#!/usr/bin/env python3
# TBH-OpenRedirect - Detector (Educational)
import requests, argparse, json, urllib.parse

BANNER = """\033[91m╔════════════════════════════════════╗
\033[91m║ \033[97mTBH-OpenRedirect \033[91m- Detector      \033[91m║
\033[91m║ \033[90mTulungagung Black Hat | uchil404 \033[91m║
\033[91m╚════════════════════════════════════╝\033[0m"""

PAYLOAD = "https://evil.com"

def check(url):
    parsed=urllib.parse.urlparse(url)
    qs=urllib.parse.parse_qs(parsed.query)
    if not qs:
        test_url=f"{url}?redirect={PAYLOAD}&next={PAYLOAD}&url={PAYLOAD}"
    else:
        # Replace first param
        k=list(qs.keys())[0]
        qs[k]=PAYLOAD
        test_url=urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(qs,doseq=True)))
    try:
        r=requests.get(test_url,timeout=5,headers={'User-Agent':'TBH-OpenRedirect/1.0'},allow_redirects=False)
        vulnerable=r.status_code in [301,302,307] and PAYLOAD in r.headers.get('Location','')
        return {"url":test_url,"status":r.status_code,"location":r.headers.get('Location',''),"vulnerable":vulnerable}
    except Exception as e:
        return {"url":test_url,"error":str(e),"vulnerable":False}

def main():
    print(BANNER)
    print("\033[91m[!] Hanya untuk scope yang diizinkan!\033[0m\n")
    parser=argparse.ArgumentParser(description="OpenRedirect")
    parser.add_argument("-u","--url",required=True)
    parser.add_argument("--json",help="Save JSON")
    args=parser.parse_args()
    print(f"[*] Testing {args.url} dengan payload: {PAYLOAD}")
    result=check(args.url)
    if result.get("vulnerable"):
        print(f"\033[91m[!] Vulnerable! {result['url']} -> {result['status']} Location: {result['location']}\033[0m")
    else:
        print(f"\033[92m[✓] Tidak vulnerable [{result.get('status')}] {result.get('location','')}\033[0m")
    if args.json:
        open(args.json,'w').write(json.dumps(result,indent=2)); print(f"[✓] JSON: {args.json}")

if __name__=="__main__": main()
