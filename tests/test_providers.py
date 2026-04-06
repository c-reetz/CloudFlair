import pytest
from providers.crtsh import CrtShProvider

def test_crtsh_cloudflare():
    """
    Test that crtsh provider works on a known cloudflare site (cloudflare.com).
    It should return subdomains that might be hosted locally or on Cloudflare.
    Then cloudflair.py filters cloudflare IPs out later.
    """
    provider = CrtShProvider()
    hosts = provider.search('cloudflare.com')
    assert isinstance(hosts, set)
    assert len(hosts) > 0

def test_crtsh_google():
    """
    Test crtsh provider on google.com (a non-cloudflare site).
    """
    provider = CrtShProvider()
    hosts = provider.search('google.com')
    assert isinstance(hosts, set)
    assert len(hosts) > 0
