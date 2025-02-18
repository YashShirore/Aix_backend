import logging
import re
from typing import Dict, List

from netaddr import IPNetwork, IPRange, IPSet

from firewall_analyzer.models.audit_result_models import (
    AuditCategory,
    AuditPriority,
    AuditResult,
    AuditGroup,
)

from .base import BaseAuditor


class AddressAuditor(BaseAuditor):
    """Class for performing firewall address object audit checks."""

    def audit_number_of_address_objects(self, **kwargs) -> AuditResult:
        """Get number of address objects.

        Returns:
            AuditResult: An object containing the audit results.
        """
        logging.debug("Getting number of for address objects...")

        if kwargs:
            matches = self._find_matches(self.parsed_config.address_objects, kwargs)

            return AuditResult(
                title=f"Count {' '.join(list(kwargs.keys()))} is {' '.join(list(kwargs.values()))}",
                category=AuditCategory.ADDRESS_OBJECTS,
                description=f"This is the number of {' '.join(list(kwargs.keys()))} is {' '.join(list(kwargs.values()))} address objects found in the configuration.",
                count=len(matches),
                raw_output=matches,
                priority=AuditPriority.INFO,
                show_raw_output=True,
            )

        else:
            return AuditResult(
                title="Count total",
                category=AuditCategory.ADDRESS_OBJECTS,
                description="This is the number of address objects found in the configuration.",
                count=len(self.parsed_config.address_objects),
                raw_output=[obj.name for obj in self.parsed_config.address_objects],
                priority=AuditPriority.INFO,
                show_raw_output=True,
            )

    def audit_address_objects_missing_description(self) -> AuditResult:
        """Audit address objects missing description.

        Returns:
            AuditResult: An object containing the audit results.
        """
        logging.debug("Auditing address objects missing description...")
        matches = [
            obj.name
            for obj in self.parsed_config.address_objects
            if not obj.description
        ]
        return AuditResult(
            title="Description Missing",
            category=AuditCategory.ADDRESS_OBJECTS,
            description="These are the address objects that are missing a description. Adding descriptions can help engineers understand the purpose of the address object.",
            count=len(matches),
            raw_output=matches,
            priority=AuditPriority.INFO,
            show_raw_output=True,
        )

    def audit_address_groups_missing_description(self) -> AuditResult:
        """Audit address groups missing description.

        Returns:
            AuditResult: An object containing the audit results.
        """
        logging.debug("Auditing address groups missing description...")
        matches = [
            obj.name for obj in self.parsed_config.address_groups if not obj.description
        ]
        return AuditResult(
            title="Description Missing",
            category=AuditCategory.ADDRESS_GROUPS,
            description="These are the address groups that are missing a description. Adding descriptions can help engineers understand the purpose of the address group.",
            count=len(matches),
            raw_output=matches,
            priority=AuditPriority.LOW,
            show_raw_output=True,
        )

    def audit_number_of_address_groups(self, **kwargs) -> AuditResult:
        """Get facts for address groups."""
        logging.debug("Getting number of for address groups...")
        if kwargs:
            matches = self._find_matches(self.parsed_config.address_groups, kwargs)
            return AuditResult(
                title=f"Count {' '.join(list(kwargs.keys()))} is {' '.join(list(kwargs.values()))}",
                category=AuditCategory.ADDRESS_GROUPS,
                description=f"This is the number of {' '.join(list(kwargs.keys()))} is {' '.join(list(kwargs.values()))} address groups found in the configuration.",
                raw_output=matches,
                count=len(matches),
                priority=AuditPriority.INFO,
            )

        else:
            return AuditResult(
                title="Count total",
                category=AuditCategory.ADDRESS_GROUPS,
                description="This is the number of address groups found in the configuration.",
                count=len(self.parsed_config.address_groups),
                raw_output=[obj.name for obj in self.parsed_config.address_groups],
                priority=AuditPriority.INFO,
            )

    def audit_unique_addresses(self) -> AuditResult:
        """Audit unique address objects.

        Returns:
            AuditResult: An object containing the audit results.
        """
        logging.debug("Auditing unique address objects...")
        matches = set(self.parsed_config.address_objects)
        return AuditResult(
            title="Unique total",
            category=AuditCategory.ADDRESS_OBJECTS,
            description="These are the address objects that are unique.",
            count=len(matches),
            raw_output=matches,
            priority=AuditPriority.INFO,
            show_raw_output=False,
        )

    def audit_duplicate_addresses_different_types(self) -> AuditResult:
        """
        Audit address objects to find exact IP matches where objects are of different types
        (e.g., one is defined as an IPRange and another as an IPNetwork).

        Returns:
            AuditResult: Contains raw_output about the audit including duplicates found.
        """
        logging.debug(
            "Starting audit for exact duplicate IP addresses with different object types..."
        )
        ip_dict = {}
        duplicates = {}

        # Iterate over all address objects and collect IP definitions
        for obj in self.parsed_config.address_objects:
            if obj.netmask:
                # Convert netmask to IPSet for comparison
                ip_set = IPSet([IPNetwork(obj.netmask)])
                ip_type = "netmask"
            elif obj.range:
                # Convert range to IPSet for comparison
                start_ip, end_ip = obj.range.split("-")
                ip_set = IPSet([IPRange(start_ip, end_ip)])
                ip_type = "range"
            else:
                continue
            ip_key = str(
                ip_set
            )  # String representation of the IP set for unique comparison
            if ip_key in ip_dict:
                # Check if existing IP key has a different type
                existing_type, names = ip_dict[ip_key]
                if ip_type != existing_type:
                    # If existing type is different, record as duplicate
                    duplicates.setdefault(ip_key, set()).update([obj.name, *names])
            else:
                # Store IP key with its type and associated names
                ip_dict[ip_key] = (ip_type, {obj.name})

        # Format the duplicates into a more readable form as a list
        duplicate_raw_output = []
        for key, names in duplicates.items():
            duplicate_raw_output.append(
                {"IPs": key, "Address Object Names": list(names)}
            )

        # Return results
        return AuditResult(
            title="Duplicate Addresses of Different Types",
            category=AuditCategory.ADDRESS_OBJECTS,
            description="Check for IP addresses objects are different types eg. netmask vs range, but same IP addresses. eg. netmask 192.168.0.0/24 and range 192.168.0.1-192.168.0.254",
            count=len(duplicate_raw_output),
            raw_output=duplicate_raw_output,
            priority=AuditPriority.LOW,
            show_raw_output=True,
            group=AuditGroup.DUPLICATES,
        )

    def audit_duplicate_addresses(self) -> AuditResult:
        """Audit duplicate address objects.

        Returns:
            AuditResult: An object containing the audit results.
        """
        logging.debug("Auditing duplicate address objects...")
        duplicates = self._find_duplicates(self.parsed_config.address_objects)
        if len(duplicates) > 0:
            recommedation = (
                "Duplicate address objects should be removed across the rulebase."
            )
        else:
            recommedation = None
        return AuditResult(
            title="Duplicates total",
            category=AuditCategory.ADDRESS_OBJECTS,
            description="Duplicates can lead to confusion and misconfiguration, produce inconsistent policy application, increased administrative overhead and increased resource consumption.",
            count=len(duplicates),
            raw_output=duplicates,
            priority=AuditPriority.LOW,
            show_raw_output=True,
            recommendation=recommedation,
            group=AuditGroup.DUPLICATES,
        )

    def audit_duplicate_addresses_with_one_duplicate(self) -> AuditResult:
        """Audit duplicate address objects with one duplicate.

        Returns:
            AuditResult: An object containing the audit results.
        """
        logging.debug("Auditing duplicate addresses with one duplicate...")
        duplicates = self._find_duplicates(self.parsed_config.address_objects)
        # For each duplicate, check if it contain only two duplicate members
        duplicates = [d for d in duplicates if len(d) == 2]
        if len(duplicates) > 0:
            recommedation = (
                "Duplicate address objects should be removed across the rulebase."
            )
        else:
            recommedation = None
        return AuditResult(
            title="    One Duplicate",
            category=AuditCategory.ADDRESS_OBJECTS,
            description="Duplicates can lead to confusion and misconfiguration, produce inconsistent policy application, increased administrative overhead and increased resource consumption.",
            count=len(duplicates),
            raw_output=duplicates,
            priority=AuditPriority.LOW,
            show_raw_output=True,
            recommendation=recommedation,
            group=AuditGroup.DUPLICATES,
        )

    def audit_duplicate_addresses_with_two_duplicates(self) -> AuditResult:
        """Audit duplicate address objects with two duplicates.

        Returns:
            AuditResult: An object containing the audit results.
        """
        logging.debug("Auditing duplicate addresses with two duplicates...")
        duplicates = self._find_duplicates(self.parsed_config.address_objects)
        # For each duplicate, check if it contain three duplicate members
        duplicates = [d for d in duplicates if len(d) == 3]
        if len(duplicates) > 0:
            recommedation = (
                "Duplicate address objects should be removed across the rulebase."
            )
        else:
            recommedation = None
        return AuditResult(
            title="    Two Duplicates",
            category=AuditCategory.ADDRESS_OBJECTS,
            description="Duplicates can lead to confusion and misconfiguration, produce inconsistent policy application, increased administrative overhead and increased resource consumption.",
            count=len(duplicates),
            raw_output=duplicates,
            priority=AuditPriority.LOW,
            show_raw_output=True,
            recommendation=recommedation,
            group=AuditGroup.DUPLICATES,
        )

    def audit_duplicate_addresses_with_three_or_more_duplicates(self) -> AuditResult:
        """Audit duplicate address objects with three or more duplicates.

        Returns:
            AuditResult: An object containing the audit results.
        """
        logging.debug("Auditing duplicate addresses with three or more duplicates...")
        duplicates = self._find_duplicates(self.parsed_config.address_objects)
        # For each duplicate, check if it contain more than three duplicate members
        duplicates = [d for d in duplicates if len(d) > 3]
        if len(duplicates) > 0:
            recommedation = (
                "Duplicate address objects should be removed across the rulebase."
            )
        else:
            recommedation = None
        return AuditResult(
            title="    Three or More Duplicates",
            category=AuditCategory.ADDRESS_OBJECTS,
            description="Duplicates can lead to confusion and misconfiguration, produce inconsistent policy application, increased administrative overhead and increased resource consumption.",
            count=len(duplicates),
            raw_output=duplicates,
            priority=AuditPriority.LOW,
            show_raw_output=True,
            recommendation=recommedation,
            group=AuditGroup.DUPLICATES,
        )

    def audit_duplicate_address_groups(self) -> AuditResult:
        """Audit duplicate address groups.

        Returns:
            AuditResult: An object containing the audit results.
        """
        logging.debug("Auditing duplicate address groups...")
        duplicates = self._find_duplicates(self.parsed_config.address_groups)
        if len(duplicates) > 0:
            recommedation = (
                "Duplicate address groups should be removed across the rulebase."
            )
        else:
            recommedation = None

        return AuditResult(
            title="Duplicates total",
            category=AuditCategory.ADDRESS_GROUPS,
            description="Duplicates can lead to confusion and misconfiguration, produce inconsistent policy application, increased administrative overhead and increased resource consumption.",
            count=len(duplicates),
            raw_output=duplicates,
            priority=AuditPriority.LOW,
            show_raw_output=True,
            recommendation=recommedation,
            group=AuditGroup.DUPLICATES,
        )

    def audit_address_objects_not_in_use(self) -> AuditResult:
        """Audit address objects not in use.

        Returns:
            AuditResult: An object containing the audit results.
        """
        logging.debug("Auditing address objects not in use...")

        # Find all address objects and address groups used in security rules
        used = set()
        for rule in self.parsed_config.security_rules:
            used.update(rule.source_address)
            used.update(rule.destination_address)

        for rule in self.parsed_config.nat_rules:
            used.update(rule.source_address)
            used.update(rule.destination_address)
            if rule.translated_destination:
                used.update(rule.translated_destination)
            if rule.translated_source:
                used.update(rule.translated_source)
        # Find the address groups that are in security rules
        # expand the group members so that all the address objects are
        # added to the used_obj_and_grp set
        for group in self.parsed_config.address_groups:
            if group.name in used:
                # expand the group members so that all the address objects are added to 'used'
                for member in group.members:
                    used.add(member)

        # Find the address objects that are not used in any security rules
        unused = []
        for address in self.parsed_config.address_objects:
            if address.name not in used:
                unused.append(address.name)

        if len(unused) > 0:
            recommendation = "Un-used address objects should be removed."
        else:
            recommendation = None

        return AuditResult(
            title="Unused total",
            category=AuditCategory.ADDRESS_OBJECTS,
            description="Unused address objects that have been defined but are not used in any Policy Rules. This can add administrative overhead.",
            count=len(unused),
            raw_output=unused,
            priority=AuditPriority.LOW,
            show_raw_output=True,
            recommendation=recommendation,
            group=AuditGroup.UNUSED,
        )

    def audit_address_groups_not_in_use(self) -> AuditResult:
        """Audit address groups not in use.

        Returns:
            AuditResult: An object containing the audit results.
        """
        logging.debug("Auditing address groups not in use...")
        # Find all address objects and address groups used in security rules
        used = set()
        for rule in self.parsed_config.security_rules:
            used.update(rule.source_address)
            used.update(rule.destination_address)

        for rule in self.parsed_config.nat_rules:
            used.update(rule.source_address)
            used.update(rule.destination_address)
            if rule.translated_destination:
                used.update(rule.translated_destination)
            if rule.translated_source:
                used.update(rule.translated_source)

        unused = []
        for group in self.parsed_config.address_groups:
            if group.name not in used:
                unused.append(group.name)

        if len(unused) > 0:
            recommendation = "Un-used address groups should be removed."
        else:
            recommendation = None
        return AuditResult(
            title="Unused total",
            category=AuditCategory.ADDRESS_GROUPS,
            description="These are the address groups that are defined but not used in any security or nat rules. This can add administrative overhead.",
            count=len(unused),
            raw_output=unused,
            priority=AuditPriority.LOW,
            show_raw_output=True,
            recommendation=recommendation,
            group=AuditGroup.UNUSED,
        )

    def audit_number_of_non_rfc1918_address_objects(self) -> AuditResult:
        """Audit number of non-RFC1918 address objects.

        Returns:
            AuditResult: An object containing the audit results.
        """
        logging.debug("Auditing number of non-RFC1918 address objects...")
        matches = []

        for address in self.parsed_config.address_objects:
            if not self._has_rfc1918_address(address):
                matches.append(address)

        return AuditResult(
            title="Non RFC1918 total",
            category=AuditCategory.ADDRESS_OBJECTS,
            description="These are the address objects that are not in the RFC1918 address space. Non RFC1918 address objects are used for public networks.",
            count=len(matches),
            raw_output=matches,
            priority=AuditPriority.INFO,
            show_raw_output=True,
        )

    def audit_address_objects_with_public_ip(self) -> AuditResult:
        """Audit address objects with public IP.

        Returns:
            AuditResult: An object containing the audit results.
        """
        logging.debug("Auditing address objects with public IP...")
        matches = []
        for address in self.parsed_config.address_objects:
            if not self._has_rfc1918_address(address):
                matches.append(address)

        return AuditResult(
            title="Public IP total",
            category=AuditCategory.ADDRESS_OBJECTS,
            description="These are the address objects that have public IP addresses. Public IP address objects are used for public networks.",
            count=len(matches),
            raw_output=matches,
            priority=AuditPriority.INFO,
            show_raw_output=True,
        )

    def audit_mismatched_address_objects(self) -> AuditResult:
        """Audit mismatched address objects.

        Returns:
            AuditResult: An object containing the audit results.
        """
        logging.debug("Auditing mismatched address objects...")
        matches = self._mismatched_addresses_combined()

        if len(matches) > 0:
            recommendation = "Investigate and rectify any misconfigurations."
        else:
            recommendation = None
        return AuditResult(
            title="Mismatched Addresses",
            category=AuditCategory.ADDRESS_OBJECTS,
            description="Mismatched Object is where the name of the object does not match the value of the address. For example, an object name being “Net_10.1.2.0-24” and the value being “10.1.3.0/24”. This indicates a misconfiguration and can lead to operational complications.",
            count=len(matches),
            raw_output=matches,
            priority=AuditPriority.MEDIUM,
            show_raw_output=True,
            recommendation=recommendation,
        )

    def _mismatched_addresses_combined(self) -> List[Dict]:
        """Combine the mismatched services identified by various rules."""
        matches = []
        matches.extend(self._variation_underscore_netmask())
        matches.extend(self._variation_hyphen_netmask())
        matches.extend(self._variation_hyphen_range())
        matches.extend(self._variation_host_ip())
        return matches

    def _variation_underscore_netmask(self) -> List[Dict]:
        """Find mismatched address object with names like 192.0.0.0_25."""
        mismatched_services = []
        pattern = r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})_(\d{1,2})$"
        for address in self.parsed_config.address_objects:
            match = re.match(pattern, address.name.lower())
            if match:
                ip_address = match.group(1)
                prefix_length = int(match.group(2))
                expected = f"{ip_address}/{prefix_length}"
                if address.netmask:
                    if expected != address.netmask:
                        mismatched_services.append(address)
        return mismatched_services

    def _variation_hyphen_netmask(self) -> List[Dict]:
        """Find mismatched address object with names like 192.168.0.0-27"""
        mismatched_services = []
        pattern = r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})-(\d{1,2})$"
        for address in self.parsed_config.address_objects:
            match = re.match(pattern, address.name.lower())
            if match:
                ip_address = match.group(1)
                prefix_length = int(match.group(2))
                expected = f"{ip_address}/{prefix_length}"
                if address.netmask:
                    if expected != address.netmask:
                        mismatched_services.append(address)
        return mismatched_services

    def _variation_host_ip(self) -> List[Dict]:
        """Find mismatched address object with names like MYADDRESS_10.169.8.150"""
        mismatched_services = []
        pattern = r"(\w+)_(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$"
        for address in self.parsed_config.address_objects:
            match = re.match(pattern, address.name, flags=re.IGNORECASE)
            if match:
                hostname = match.group(2)
                expected = f"{hostname}"
                if address.netmask:
                    if (
                        expected != address.netmask
                        and f"{expected}/32" != address.netmask
                    ):
                        mismatched_services.append(address)
        return mismatched_services

    def _variation_hyphen_range(self) -> List[Dict]:
        """Find mismatched address object with names like Range_10.188.92.46-10.188.92.48"""
        mismatched_services = []
        pattern = r"range_(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})-(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$"
        for address in self.parsed_config.address_objects:
            match = re.match(pattern, address.name.lower())
            if match:
                start_ip = match.group(1)
                end_ip = match.group(2)
                expected = f"{start_ip}-{end_ip}"
                if address.range:
                    if expected != address.range:
                        mismatched_services.append(address)
        return mismatched_services
