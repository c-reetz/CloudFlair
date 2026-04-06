import sys
import os
from .base import BaseProvider

try:
    from censys_platform import SDK
    from censys_platform.exceptions import CensysException
except ImportError:
    pass

CERT_CHUNK_SIZE = 25
INVALID_CREDS = "[-] Your Censys Platform credentials look invalid. Are you using a Personal Access Token?\n"
RATE_LIMIT = "[-] Looks like you exceeded your Censys Platform account limits rate. Exiting\n"

class CensysPlatformProvider(BaseProvider):
    def __init__(self, api_token):
        if 'censys_platform' not in sys.modules:
            sys.stderr.write("[-] Missing 'censys-platform' library. Install it with pip.\n")
            exit(1)
        self.api_token = api_token

    def get_certificates(self, domain: str) -> set:
        try:
            sdk = SDK(personal_access_token=self.api_token)
            
            # Using unified search from CensysPlatformClient for certificates
            query = f'cert.names: {domain} and cert.parsed.signature.valid: true and not cert.names: cloudflaressl.com'
            
            # Search global data 
            response = sdk.global_search.search(
                query=query, 
                resource_type="certificate",
                per_page=100
            )

            fingerprints = set()
            # Extract fingerprint from the search response
            for hit in response.get("hits", []):
                if 'cert.fingerprint_sha256' in hit:
                    fingerprints.add(hit['cert.fingerprint_sha256'])
                elif 'fingerprint_sha256' in hit:
                    fingerprints.add(hit['fingerprint_sha256'])
            return fingerprints
        except Exception as e:
            if "Unauthorized" in str(e) or getattr(e, 'status_code', 0) == 401:
                sys.stderr.write(INVALID_CREDS)
                exit(1)
            elif "Rate limit" in str(e) or getattr(e, 'status_code', 0) == 429:
                sys.stderr.write(RATE_LIMIT)
                exit(1)
            sys.stderr.write(f"[-] Censys Platform Error: {e}\n")
            return set()

    def get_ips_by_cert(self, cert_fingerprints: set) -> set:
        if not cert_fingerprints:
            return set()
            
        cert_fingerprints_list = list(cert_fingerprints)
        try:
            sdk = SDK(personal_access_token=self.api_token)
            
            hosts = set()
            for fp in cert_fingerprints_list:
                query = f'host.services.tls.certificates.leaf_data.fingerprint_sha256="{fp}"'
                response = sdk.global_search.search(
                    query=query,
                    resource_type="host",
                    per_page=100
                )
                
                for hit in response.get("hits", []):
                    ip = hit.get("host.ip") or hit.get("ip")
                    if ip:
                        # Extract the IP string, it might be a list sometimes
                        if isinstance(ip, list) and len(ip) > 0:
                            hosts.add(ip[0])
                        elif isinstance(ip, str):
                            hosts.add(ip)

            return hosts
        except Exception as e:
            if "Unauthorized" in str(e) or getattr(e, 'status_code', 0) == 401:
                sys.stderr.write(INVALID_CREDS)
                exit(1)
            elif "Rate limit" in str(e) or getattr(e, 'status_code', 0) == 429:
                sys.stderr.write(RATE_LIMIT)
                exit(1)
            sys.stderr.write(f"[-] Censys Platform Error: {e}\n")
            return set()

    def search(self, domain: str) -> set:
        print('[*] Looking for certificates matching "%s" using Censys Platform' % domain)
        cert_fingerprints = self.get_certificates(domain)
        cert_fingerprints_list = list(cert_fingerprints)
        cert_fingerprints_count = len(cert_fingerprints_list)
        print('[*] %d certificates matching "%s" found.' % (cert_fingerprints_count, domain))

        if cert_fingerprints_count == 0:
            return set()

        chunking = (cert_fingerprints_count > CERT_CHUNK_SIZE)
        if chunking:
            print(f'[*] Splitting the list of certificates into chunks of {CERT_CHUNK_SIZE}.')

        print('[*] Looking for IPv4 hosts presenting these certificates...')
        hosts = set()
        
        # New API doesn't support `{fp1, fp2}` easily in some cases, so we might chunk internally
        # if the query gets too long. Usually, we can do `fp="a" or fp="b"`
        for i in range(0, cert_fingerprints_count, CERT_CHUNK_SIZE):
            if chunking:
                print('[*] Processing chunk %d/%d' % (i/CERT_CHUNK_SIZE + 1, cert_fingerprints_count/CERT_CHUNK_SIZE + 1))
            hosts.update(self.get_ips_by_cert(set(cert_fingerprints_list[i:i+CERT_CHUNK_SIZE])))
            
        return hosts
