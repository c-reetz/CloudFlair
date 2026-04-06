import sys
import requests
from typing import Set
from .base import BaseProvider

class ShodanProvider(BaseProvider):
    def __init__(self, api_key: str): # Only requires one API key
        self.api_key = api_key

    def get_ips_by_cert(self, fingerprints: Set[str]) -> Set[str]:
        if not self.api_key:
            return set()
            
        hosts = set()
        
        for fingerprint in fingerprints:
            # Shodan uses raw fingerprints, often without colons, or with colons
            # Example: ssl.cert.fingerprint:15:06:66... or just hex.
            # Usually it requires colons, let's format it.
            # Convert simple hex string 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
            # to 'e3:b0:c4:42:98:fc...' if it doesn't have colons.
            fp = fingerprint.replace(':', '').lower()
            formatted_fp = ':'.join(float[i:i+2] for i in range(0, len(fp), 2)) if 'float' not in locals() else ':'.join(a+b for a,b in zip(fp[::2], fp[1::2]))
            
            # actually better:
            formatted_fp = ':'.join(a+b for a,b in zip(fp[::2], fp[1::2]))
            
            url = f"https://api.shodan.io/shodan/host/search?key={self.api_key}&query=ssl.cert.fingerprint:{formatted_fp}"
            try:
                response = requests.get(url, timeout=15)
                if response.status_code == 401:
                    sys.stderr.write("[-] Invalid Shodan API key.\n")
                    break # stop trying if unauthorized
                elif response.status_code == 403:
                    sys.stderr.write("[-] Shodan API access restricted or rate limit exceeded.\n")
                    break
                elif response.status_code == 200:
                    data = response.json()
                    for match in data.get('matches', []):
                        hosts.add(match.get('ip_str'))
            except Exception as e:
                print(f"[-] Failed to query Shodan: {e}")
                
        return hosts

    def search(self, domain: str) -> Set[str]:
        # Shodan doesn't easily let us find certs by domain without the 'ssl.cert.subject.cn' query 
        # which uses heavy query credits. So we only act as an IP scanning provider here for now.
        return set()
