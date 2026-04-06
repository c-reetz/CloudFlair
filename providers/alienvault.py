import requests
from typing import Set
from .base import BaseProvider

class AlienVaultProvider(BaseProvider):
    def __init__(self):
        pass # No API key required for this endpoint generally, or not strict

    def get_subdomains(self, domain: str) -> Set[str]:
        subdomains = set()
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        
        try:
            print(f"[*] Querying AlienVault OTX for subdomains of {domain}...")
            # Use headers to appear somewhat normal
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            response = requests.get(url, headers=headers, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                for record in data.get('passive_dns', []):
                    hostname = record.get('hostname')
                    if hostname and hostname.endswith(domain):
                        subdomains.add(hostname)
            else:
                print(f"[-] AlienVault OTX returned status {response.status_code}")
                
        except Exception as e:
            print(f"[-] Failed to query AlienVault OTX: {e}")
            
        print(f"[*] Found {len(subdomains)} unique subdomains from AlienVault OTX.")
        return subdomains

    def search(self, domain: str) -> Set[str]:
        return set()
