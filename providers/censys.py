import sys
from censys.common.exceptions import (
    CensysRateLimitExceededException,
    CensysUnauthorizedException,
)
from censys.search import CensysCerts, CensysHosts
from .base import BaseProvider

USER_AGENT = f"{CensysCerts.DEFAULT_USER_AGENT} (CloudFlair; +https://github.com/christophetd/CloudFlair)"
INVALID_CREDS = "[-] Your Censys credentials look invalid.\n"
RATE_LIMIT = "[-] Looks like you exceeded your Censys account limits rate. Exiting\n"
CERT_CHUNK_SIZE = 25

class CensysProvider(BaseProvider):
    def __init__(self, api_id, api_secret):
        self.api_id = api_id
        self.api_secret = api_secret

    def get_certificates(self, domain: str, pages=2) -> set:
        try:
            censys_certificates = CensysCerts(
                api_id=self.api_id, api_secret=self.api_secret, user_agent=USER_AGENT
            )

            certificate_query = f"names: {domain} and parsed.signature.valid: true and not names: cloudflaressl.com"
            certificates_search_results = censys_certificates.search(
                certificate_query, per_page=100, pages=pages
            )

            fingerprints = set()
            for page in certificates_search_results:
                for cert in page:
                    fingerprints.add(cert["fingerprint_sha256"])
            return fingerprints
        except CensysUnauthorizedException:
            sys.stderr.write(INVALID_CREDS)
            exit(1)
        except CensysRateLimitExceededException:
            sys.stderr.write(RATE_LIMIT)
            exit(1)

    def get_ips_by_cert(self, cert_fingerprints: set) -> set:
        cert_fingerprints_list = list(cert_fingerprints)
        try:
            censys_hosts = CensysHosts(
                api_id=self.api_id, api_secret=self.api_secret, user_agent=USER_AGENT
            )
            hosts_query = f"services.tls.certificates.leaf_data.fingerprint: {{{','.join(cert_fingerprints_list)}}}"
            hosts_search_results = censys_hosts.search(hosts_query).view_all()
            return set(
                [r["ip"] for r in hosts_search_results.values()]
            )
        except CensysUnauthorizedException:
            sys.stderr.write(INVALID_CREDS)
            exit(1)
        except CensysRateLimitExceededException:
            sys.stderr.write(RATE_LIMIT)
            exit(1)

    def search(self, domain: str) -> set:
        print('[*] Looking for certificates matching "%s" using Censys' % domain)
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
        for i in range(0, cert_fingerprints_count, CERT_CHUNK_SIZE):
            if chunking:
                print('[*] Processing chunk %d/%d' % (i/CERT_CHUNK_SIZE + 1, cert_fingerprints_count/CERT_CHUNK_SIZE))
            hosts.update(self.get_ips_by_cert(cert_fingerprints_list[i:i+CERT_CHUNK_SIZE]))
            
        return hosts
