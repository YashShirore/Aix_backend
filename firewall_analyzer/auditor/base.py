import logging
from typing import List, Any, Dict

from firewall_analyzer.models.firewall_models import (
    FirewallConfiguration,
    AddressObject,
)
from netaddr import IPRange, IPNetwork


class BaseAuditor:
    """Parent class for performing firewall audit checks."""

    rfc1918_ranges = [
        IPNetwork("10.0.0.0/8"),
        IPNetwork("172.16.0.0/12"),
        IPNetwork("192.168.0.0/16"),
    ]

    def __init__(self, parsed_config: FirewallConfiguration):
        """
        Initialize the BaseAuditor class.

        Args:
            parsed_config (FirewallConfiguration): The parsed firewall configuration.
        """
        self.parsed_config = parsed_config
        self.cache = {}  # Global cache dictionary

    def _find_duplicates(self, objects: List[Any]) -> List[List[Any]]:
        """
        Finds and returns a list of duplicate objects in the given list.

        Args:
            objects (List[Any]): A list of objects to search for duplicates.

        Returns:
            List[List[Any]]: A list of lists, where each inner list contains the duplicate objects found.

        """
        count: Dict[Any, List[Any]] = {}

        for obj in objects:
            if obj in count:
                count[obj].append(obj)
            else:
                count[obj] = [obj]

        duplicates = [objs for objs in count.values() if len(objs) > 1]

        return duplicates

    def _find_matches(self, items, kwargs) -> set:
        """
        Finds matches in a collection of items based on the provided keyword arguments.

        Args:
            items (iterable): The collection of items to search for matches.
            kwargs (dict): The keyword arguments used to filter the items.

        Returns:
            Set[str]: A set of names of the items that match the provided criteria.
        """
        matches = set()
        for obj in items:
            for key, value in kwargs.items():
                if hasattr(obj, key):
                    if value in getattr(obj, key):
                        matches.add(obj.name)
        return matches

    def _find_unique(self, items, key_function) -> set:
        """
        Find unique objects based on a key function.

        Args:
            items (List[Any]): The collection of items to search for unique objects.
            key_function (Callable[[Any], str]): The function to extract a key from each item.

        Returns:
            Set[str]: A set of strings representing the unique objects.
        """
        unique = set()
        for obj in items:
            key = key_function(obj)
            unique.add(key)
        return unique

    def _has_rfc1918_address(self, address: AddressObject) -> bool:
        """
        Check if the given address contains an RFC1918 address.

        Args:
            address (AddressObject): The address object to check.

        Returns:
            bool: True if the address contains an RFC1918 address, False otherwise.
        """
        if address.range:
            ip_range = IPRange(address.range.split("-")[0], address.range.split("-")[1])
            if any(ip_range in rfc1918_range for rfc1918_range in self.rfc1918_ranges):
                return True
        elif address.netmask:
            ip_network = IPNetwork(address.netmask)
            if any(
                ip_network in rfc1918_range for rfc1918_range in self.rfc1918_ranges
            ):
                return True
        return False
