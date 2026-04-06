from abc import ABC, abstractmethod
from typing import Set

class BaseProvider(ABC):
    @abstractmethod
    def search(self, domain: str) -> Set[str]:
        """
        Search for potential origin server IPv4 addresses for the given domain.
        Returns a set of IPv4 strings.
        """
        pass
