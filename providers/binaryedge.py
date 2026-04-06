import sys
import requests
from typing import Set
from .base import BaseProvider

class BinaryEdgeProvider(BaseProvider):
    def __init__(self, api_key: str, check_subdomains=False):
        super().__init__(check_subdomains)
        self.api_key = api_key
        self.headers = {'X-Key': self.api_key}

    def get_subdomains(self, domain: str) -> Set[str]:
        if not self.api_key:
            return set()
            
        subdomains = set()
        
        if not self.check_subdomains:
             # Binaryedge Domain API isn't exactly mapping 1:1 for "exact" vs "subdomains", 
             # but we'll stick to not pulling if the flag is off to stay consistent.
             return subdomains
             
        url = f"https://api.binaryedge.io/v2/query/domains/subdomain/{domain}"
        
        try:
            print(f"[*] Querying BinaryEdge for subdomains of {domain}...")
            response = requests.get(url, headers=self.headers, timeout=15)
            if response.status_code == 401 or response.status_code == 403:
                sys.stderr.write("[-] BinaryEdge API access denied or limit exceeded.\n")
                return set()
            elif response.status_code == 200:
                data = response.json()
                for evt in data.get('events', []):
                    subdomains.add(evt)
            else:
                print(f"[-] BinaryEdge Subdomain API returned {response.status_code}")
        except Exception as e:
            print(f"[-] Failed to query BinaryEdge for subdomains: {e}")
            
        print(f"[*] Found {len(subdomains)} unique subdomains from BinaryEdge.")
        return subdomains

    def get_ips_by_cert(self, fingerprints: Set[str]) -> Set[str]:
        if not self.api_key:
            return set()
            
        hosts = set()
        
        for fingerprint in fingerprints:
            # Format fingerprint properly if needed
            fp = fingerprint.replace(':', '').lower()
            formatted_fp = ':'.join(a+b for a,b in zip(fp[::2], fp[1::2]))
            
            url = f"https://api.binaryedge.io/v2/query/search?query=ssl.cert.sha256_fingerprint:\"{formatted_fp}\""
            try:
                response = requests.get(url, headers=self.headers, timeout=15)
                if response.status_code == 401:
                    sys.stderr.write("[-] Invalid BinaryEdge API key.\n")
                    break 
                elif response.status_code == 403:
                    sys.stderr.write("[-] BinaryEdge API access restricted or rate limit exceeded.\n")
                    break
                elif response.status_code == 200:
                    data = response.json()
                    for event in data.get('events', []):
                        if 'target' in event and 'ip' in event['target']:
                            hosts.add(event['target']['ip'])
            except Exception as e:
                print(f"[-] Failed to query BinaryEdge for IP: {e}")
                
        return hosts

    def search(self, domain: str) -> Set[str]:
        # Implementation of search is deferred to the main cloudflair sequence
        # to prevent duplicate data gathering across providers
        return set()
