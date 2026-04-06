import sys
import requests
from typing import Set
from .base import BaseProvider

class CertKitProvider(BaseProvider):
    def __init__(self, api_key: str, check_subdomains=False):
        super().__init__(check_subdomains)
        self.api_key = api_key

    def get_subdomains(self, domain: str) -> Set[str]:
        if not self.api_key:
            return set()
            
        subdomains = set()
        # Note: Depending on CertKit's actual live API endpoints, this URL might need updating.
        # This is built around standard CT search behaviors typical for such platforms.
        include_sub_str = "true" if self.check_subdomains else "false"
        url = f"https://api.certkit.io/v1/certs/search?domain={domain}&include_subdomains={include_sub_str}"
        headers = {'Authorization': f'Bearer {self.api_key}'}
        
        try:
            print(f"[*] Querying CertKit.io for subdomains of {domain}...")
            response = requests.get(url, headers=headers, timeout=15)
            if response.status_code == 401 or response.status_code == 403:
                sys.stderr.write("[-] CertKit API access denied or limit exceeded.\n")
                return set()
            elif response.status_code == 200:
                data = response.json()
                # Supposing data returns a list of cert objects with 'subject_dn' or 'san'
                for cert in data.get('data', []):
                    # add subject
                    cn = cert.get('common_name', '')
                    if cn and cn.endswith(domain) and not cn.startswith('*'):
                        subdomains.add(cn)
                    # add SANs
                    for san in cert.get('subject_alternative_names', []):
                        if san.endswith(domain) and not san.startswith('*'):
                            subdomains.add(san)
            else:
                print(f"[-] CertKit API returned status {response.status_code}")
        except Exception as e:
            print(f"[-] Failed to query CertKit: {e}")
            
        print(f"[*] Found {len(subdomains)} unique subdomains from CertKit.io.")
        return subdomains

    def search(self, domain: str) -> Set[str]:
        return set()
