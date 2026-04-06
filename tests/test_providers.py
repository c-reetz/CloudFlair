import pytest
from providers.crtsh import CrtShProvider
from providers.alienvault import AlienVaultProvider

def test_crtsh_cloudflare():
    """
    Test that crtsh provider gets subdomains and IPs 
    """
    provider = CrtShProvider()
    subdomains = provider.get_subdomains('cloudflair.xyz')
    assert isinstance(subdomains, set)
    hosts = provider.search('cloudflair.xyz')
    assert isinstance(hosts, set)

def test_alienvault_cloudflare():
    """
    Test alienvault provider on a domain proxy
    """
    provider = AlienVaultProvider()
    subdomains = provider.get_subdomains('google.com')
    assert isinstance(subdomains, set)

