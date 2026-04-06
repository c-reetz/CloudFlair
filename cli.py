import argparse

parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)

parser.add_argument(
    'domain',
    help = 'The domain to scan'
)

parser.add_argument(
    '-o', '--output',
    help = 'A file to output likely origin servers to',
    dest = 'output_file'
)

parser.add_argument(
    '--provider',
    help = 'Which provider to use for finding candidate IPs (censys or crtsh)',
    choices=['censys', 'crtsh'],
    dest = 'provider',
    default=None
)

parser.add_argument(
    '--check-subdomains',
    help = 'Query crt.sh for subdomains (*.domain) instead of exact domain match. Specifically used by the crtsh provider.',
    dest = 'check_subdomains',
    action = 'store_true',
    default = False
)

parser.add_argument(
    '--censys-api-id',
    help = 'Censys API ID. Can also be defined using the CENSYS_API_ID environment variable',
    dest = 'censys_api_id'
)

parser.add_argument(
    '--censys-api-secret',
    help = 'Censys API secret. Can also be defined using the CENSYS_API_SECRET environment variable',
    dest = 'censys_api_secret'
)

parser.add_argument(
    '--shodan-api-key',
    help = 'Shodan API Key. Can also be defined using the SHODAN_API_KEY environment variable',
    dest = 'shodan_api_key'
)

parser.add_argument(
    '--binaryedge-api-key',
    help = 'BinaryEdge API Key. Can also be defined using the BINARYEDGE_API_KEY environment variable',
    dest = 'binaryedge_api_key'
)

parser.add_argument(
    '--certkit-api-key',
    help = 'CertKit API Key. Can also be defined using the CERTKIT_API_KEY environment variable',
    dest = 'certkit_api_key'
)

parser.add_argument(
    '--cloudfront',
    help = 'Check Cloudfront instead of CloudFlare.',
    dest = 'use_cloudfront',
    action='store_true',
    default=False
)
