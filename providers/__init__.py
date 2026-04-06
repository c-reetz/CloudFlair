from .base import BaseProvider
from .censys import CensysProvider
from .crtsh import CrtShProvider

def get_provider(provider_name: str, **kwargs) -> BaseProvider:
    if provider_name == 'censys':
        return CensysProvider(kwargs.get('api_id'), kwargs.get('api_secret'))
    elif provider_name == 'crtsh':
        return CrtShProvider(check_subdomains=kwargs.get('check_subdomains', False))
    else:
        raise ValueError(f"Unknown provider: {provider_name}")
