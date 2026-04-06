import requests
import dns.resolver
from .base import BaseProvider

class CrtShProvider(BaseProvider):
    def __init__(self, check_subdomains=False):
        self.check_subdomains = check_subdomains

    def search(self, domain: str) -> set:
        prefix = "%." if self.check_subdomains else ""
        action_word = "subdomains of " if self.check_subdomains else ""
        print(f'[*] Querying crt.sh for {action_word}{domain}...')
        url = f"https://crt.sh/?q={prefix}{domain}&output=json"
        
        try:
            response = requests.get(url, timeout=15)
            if response.status_code != 200:
                print(f"[-] crt.sh responded with status code {response.status_code}")
                return set()
            data = response.json()
        except Exception as e:
            print(f"[-] Failed to query crt.sh: {e}")
            return set()

        subdomains = set()
        for entry in data:
            name_value = entry.get('name_value', '')
            for sub in name_value.split('\n'):
                sub = sub.strip()
                if sub and not sub.startswith('*'):
                    subdomains.add(sub)
                    
        print(f"[*] Found {len(subdomains)} unique subdomains from crt.sh.")
        
        hosts = set()
        print("[*] Resolving subdomains to IPv4 addresses...")
        for sub in subdomains:
            try:
                # Use resolve() for dnspython >= 2.0.0
                if hasattr(dns.resolver, 'resolve'):
                    answers = dns.resolver.resolve(sub, 'A')
                else: # Fallback for dnspython < 2.0.0
                    answers = dns.resolver.query(sub, 'A')
                    
                for rdata in answers:
                    if hasattr(rdata, 'address'):
                        hosts.add(rdata.address)
                    else:
                        hosts.add(str(rdata))
            except Exception:
                pass
                
        return hosts
