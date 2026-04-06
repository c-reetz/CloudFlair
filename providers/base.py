from abc import ABC, abstractmethod
from typing import Set

class BaseProvider(ABC):
    def get_subdomains(self, domain: str) -> Set[str]:
        """Search for potential subdomains related to the domain."""
        return set()

    def get_certificates(self, domain: str) -> Set[str]:
        """Search for potential certificate fingerprints (SHA-256 or SHA-1 strings) related to the domain."""
        return set()

    def get_ips_by_cert(self, fingerprints: Set[str]) -> Set[str]:
        """Search for IPs presenting the given certificate fingerprints."""
        return set()
    
    @abstractmethod
    def search(self, domain: str) -> Set[str]:
        """Search for potential origin server IPv4 addresses for the given domain."""
        pass
