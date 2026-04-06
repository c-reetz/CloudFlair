import requests
from typing import Set
from .base import BaseProvider

class AlienVaultProvider(BaseProvider):
    def __init__(self, check_subdomains=False):
        super().__init__(check_subdomains)
        pass #todo: add API key auth....

    def get_subdomains(self, domain: str) -> Set[str]:
        subdomains = set()
        
        if not self.check_subdomains:
            # AlienVault OTX passive DNS naturally returns all observed subdomains.
            # If check_subdomains is false, should we only look for the exact domain?
            # It's an IP discovery tool, so we can stick to checking subdomains only if flagged.
            return subdomains
            
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        
        try:
            print(f"[*] Querying AlienVault OTX for subdomains of {domain}...")
            response = requests.get(url, timeout=15)
            
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
