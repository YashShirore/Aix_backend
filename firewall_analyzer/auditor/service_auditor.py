import logging
import re
from typing import Dict, List

from firewall_analyzer.models.audit_result_models import (
    AuditCategory,
    AuditPriority,
    AuditResult,
)

from .base import BaseAuditor


class ServiceAuditor(BaseAuditor):
    """Class for performing firewall service audit checks."""

    def audit_number_of_service_objects(self, **kwargs) -> AuditResult:
        """Get facts for service objects."""
        logging.debug("Getting facts for service objects...")
        if kwargs:
            matches = self._find_matches(self.parsed_config.service_objects, kwargs)

            return AuditResult(
                title=f"Count {' '.join(list(kwargs.keys()))} is {' '.join(list(kwargs.values()))}",
                category=AuditCategory.SERVICE_OBJECTS,
                description=f"This is the number of {' '.join(list(kwargs.keys()))} is {' '.join(list(kwargs.values()))} service objects found in the configuration.",
                raw_output=matches,
                count=len(matches),
                priority=AuditPriority.INFO,
            )
        else:
            return AuditResult(
                title="Count total",
                category=AuditCategory.SERVICE_OBJECTS,
                description="This is the number of service objects found in the configuration.",
                count=len(self.parsed_config.service_objects),
                raw_output=[obj.name for obj in self.parsed_config.service_objects],
                priority=AuditPriority.INFO,
            )

    def audit_service_objects_missing_description(self) -> AuditResult:
        """Audit service objects missing description.

        Returns:
            AuditResult: An object containing the audit results.
        """
        logging.debug("Auditing service objects missing description...")
        matches = [
            obj.name
            for obj in self.parsed_config.service_objects
            if not obj.description
        ]
        if len(matches) > 0:
            recommedation = "Adding descriptions to assist engineers in understanding the purpose of the service object."
        else:
            recommedation = None
        return AuditResult(
            title="Description Missing",
            category=AuditCategory.SERVICE_OBJECTS,
            description="These are the service objects that are missing a description.",
            count=len(matches),
            raw_output=matches,
            priority=AuditPriority.MEDIUM,
            show_raw_output=True,
            recommendation=recommedation,
        )

    def audit_number_of_service_groups(self, **kwargs) -> AuditResult:
        """Get facts for service groups."""
        logging.debug("Getting facts for service groups...")

        if kwargs:
            matches = self._find_matches(self.parsed_config.service_groups, kwargs)
            return AuditResult(
                title=f"Count {' '.join(list(kwargs.keys()))} is {' '.join(list(kwargs.values()))}",
                category=AuditCategory.SERVICE_GROUPS,
                description=f"This is the number of {' '.join(list(kwargs.keys()))} is {' '.join(list(kwargs.values()))} service groups found in the configuration.",
                raw_output=matches,
                count=len(matches),
                priority=AuditPriority.INFO,
            )
        else:
            return AuditResult(
                title="Count total",
                category=AuditCategory.SERVICE_GROUPS,
                description="This is the number of service groups found in the configuration.",
                count=len(self.parsed_config.service_groups),
                raw_output=[obj.name for obj in self.parsed_config.service_groups],
                priority=AuditPriority.INFO,
            )

    def audit_service_groups_missing_description(self) -> AuditResult:
        """Audit service groups missing description.

        Returns:
            AuditResult: An object containing the audit results.
        """
        logging.debug("Auditing service groups missing description...")
        matches = [
            obj.name for obj in self.parsed_config.service_groups if not obj.description
        ]
        if len(matches) > 0:
            recommedation = "Adding descriptions to assist engineers in understanding the purpose of the service group."
        else:
            recommedation = None
        return AuditResult(
            title="Description Missing",
            category=AuditCategory.SERVICE_GROUPS,
            description="These are the service groups that are missing a description.",
            count=len(matches),
            raw_output=matches,
            priority=AuditPriority.MEDIUM,
            show_raw_output=True,
            recommendation=recommedation,
        )

    def audit_duplicate_service_groups(self) -> AuditResult:
        """Audit duplicate service groups.

        Returns:
            AuditResult: An object containing the audit results.
        """
        logging.debug("Auditing duplicate service groups...")
        duplicates = self._find_duplicates(self.parsed_config.service_groups)
        if len(duplicates) > 0:
            recommedation = "Remove duplicates to avoid confusion and misconfiguration."
        else:
            recommedation = None
        return AuditResult(
            title="Duplicates total",
            category=AuditCategory.SERVICE_GROUPS,
            description="These are the service groups that have the same members. Having duplicate service groups can lead to confusion and misconfiguration.",
            count=len(duplicates),
            raw_output=duplicates,
            priority=AuditPriority.LOW,
            show_raw_output=True,
            recommendation=recommedation,
        )

    def audit_duplicate_service_objects(self) -> AuditResult:
        """Audit duplicate service objects.

        Returns:
            AuditResult: An object containing the audit results.
        """
        logging.debug("Auditing duplicate service objects...")

        duplicates = self._find_duplicates(self.parsed_config.service_objects)
        if len(duplicates) > 0:
            recommedation = "Remove duplicates to avoid confusion and misconfiguration."
        else:
            recommedation = None

        return AuditResult(
            title="Duplicates total",
            category=AuditCategory.SERVICE_OBJECTS,
            description="These are the service objects that have the same protocol and port. Having duplicate service objects can lead to confusion and misconfiguration.",
            count=len(duplicates),
            raw_output=duplicates,
            priority=AuditPriority.LOW,
            show_raw_output=True,
            recommendation=recommedation,
        )

    def audit_mismatched_service_objects(self) -> AuditResult:
        """Audit mismatched service objects.

        Returns:
            AuditResult: An object containing the audit results.
        """
        logging.debug("Auditing mismatched service objects...")
        mismatched_services = self._mismatched_services_combined()
        if len(mismatched_services) > 0:
            recommedation = "Invetigate and recify the mismatched service objects."
        else:
            recommedation = None
        return AuditResult(
            title="Mismatched Services",
            category=AuditCategory.SERVICE_OBJECTS,
            description="These are the service objects where the name of the object does not match the protocol or port number. This indicates a misconfiguration and can lead to operational complications.",
            count=len(mismatched_services),
            raw_output=mismatched_services,
            priority=AuditPriority.HIGH,
            show_raw_output=True,
            recommendation=recommedation,
        )

    def _mismatched_services_combined(self) -> List[Dict]:
        """Combine the mismatched services identified by various rules."""
        mismatched_services = []
        mismatched_services.extend(self._variation_tcp_udp_name())
        mismatched_services.extend(self._variation_single_port())
        mismatched_services.extend(self._variation_port_range())
        return mismatched_services

    def _variation_tcp_udp_name(self) -> List[Dict]:
        """Find mismatched services where the name contains 'tcp' or 'udp'."""
        mismatched_services = []
        for service in self.parsed_config.service_objects:
            for expected_protocol in ["tcp", "udp", "icmp"]:
                if expected_protocol in service.name.lower():
                    if service.protocol != expected_protocol:
                        mismatched_services.append(service)
        return mismatched_services

    def _variation_single_port(self) -> List[Dict]:
        """Find mismatched services with names like T123 or U456."""
        mismatched_services = []
        pattern = r"^([tu])(\d+)$"
        for service in self.parsed_config.service_objects:
            match = re.match(pattern, service.name.lower())
            if match:
                expected_protocol = "tcp" if match.group(1) == "t" else "udp"
                expected_port = match.group(2)
                if (
                    service.protocol != expected_protocol
                    or service.port != expected_port
                ):
                    mismatched_services.append(service)
        return mismatched_services

    def _variation_port_range(self) -> List[Dict]:
        """Find mismatched services with names like T123-125 or U100-110."""
        mismatched_services = []
        pattern = r"([tu])(\d+)-(\d+)"
        for service in self.parsed_config.service_objects:
            match = re.match(pattern, service.name.lower())
            if match:
                expected_protocol = "tcp" if match.group(1) == "t" else "udp"
                start_port = match.group(2)
                end_port = self._extend_port_range(start_port, match.group(3))
                expected_range = f"{start_port}-{end_port}"
                if (
                    service.protocol != expected_protocol
                    or service.port != expected_range
                ):
                    mismatched_services.append(service)
        return mismatched_services

    def _extend_port_range(self, start: str, end: str) -> str:
        """Extend the port range by aligning the length difference."""
        if len(start) > len(end):
            prefix_length = len(start) - len(end)
            end_extended = int(start[:prefix_length] + end)
            return str(end_extended)
        return end

    def audit_service_objects_not_in_use(self) -> AuditResult:
        """Audit service objects not in use.

        Returns:
            AuditResult: An object containing the audit results.
        """
        logging.debug("Auditing service objects not in use...")

        # Find all service objects and service groups used in security rules
        used = set()
        for rule in self.parsed_config.security_rules:
            used.update(rule.destination_service)

        # Find the service groups that are in security rules
        # expand the group members so that all the service objects are
        # added to the used_obj_and_grp set
        for group in self.parsed_config.service_groups:
            if group.name in used:
                # expand the group members so that all the service objects are added to 'used'
                for member in group.members:
                    used.add(member)

        # Find the service objects that are not used in any security rules
        unused = []
        for service in self.parsed_config.service_objects:
            if service.name not in used:
                unused.append(service.name)

        if len(unused) > 0:
            recommedation = (
                "Remove unused service objects to avoid operational maintainence."
            )
        else:
            recommedation = None

        return AuditResult(
            title="Unused total",
            category=AuditCategory.SERVICE_OBJECTS,
            description="These are the service objects that are defined but not used in any security rules. Unused service objects can add operational maintainence.",
            count=len(unused),
            raw_output=unused,
            priority=AuditPriority.LOW,
            show_raw_output=True,
            recommendation=recommedation,
        )

    def audit_service_groups_not_in_use(self) -> AuditResult:
        """Audit service groups not in use.

        Returns:
            AuditResult: An object containing the audit results.
        """
        logging.debug("Auditing service groups not in use...")

        # Find all service objects and service groups used in security rules
        used = set()
        for rule in self.parsed_config.security_rules:
            used.update(rule.destination_service)

        unused = []
        for group in self.parsed_config.service_groups:
            if group.name not in used:
                unused.append(group.name)

        if len(unused) > 0:
            recommedation = (
                "Remove unused service groups to reduce operational maintainence."
            )
        else:
            recommedation = None

        return AuditResult(
            title="Unused total",
            category=AuditCategory.SERVICE_GROUPS,
            description="These are the service groups that are defined but not used in any security rules. Unused service groups can add operational maintainence.",
            count=len(unused),
            raw_output=unused,
            priority=AuditPriority.LOW,
            show_raw_output=True,
            recommendation=recommedation,
        )
