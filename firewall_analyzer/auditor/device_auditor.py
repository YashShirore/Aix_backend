import logging
import re
from typing import List

from firewall_analyzer.models.audit_result_models import (
    AuditCategory,
    AuditPriority,
    AuditResult,
)

from .base import BaseAuditor


class DeviceAuditor(BaseAuditor):
    """Class for performing device audit checks."""

    def audit_number_of_devices(self) -> AuditResult:
        """
        Check the number of devices.
            
        Returns:
            AuditResult: An object containing the audit results.
        """
        logging.debug("Getting devices...")

        return AuditResult(
            title="Count total",
            category=AuditCategory.DEVICE,
            description="This is the number of devices found in the configuration.",
            count=len(self.parsed_config.devices),
            raw_output=self.parsed_config.devices,
            show_raw_output=True,
            priority=AuditPriority.INFO,
        )

    def audit_snmp_default_community(self) -> List[AuditResult]:
        """
        Check if the SNMP community value is set to the default ("public").
            
        Returns:
            List[AuditResult]: A list containing audit results for all devices.
        """
        logging.debug("Auditing SNMP community default...")

        results = []  # Store results for all devices
        for device in self.parsed_config.devices:
            if device.snmp_community == "public":
                count = 1
                recommendation = "Change the SNMP community string to a more secure value."
                priority = AuditPriority.HIGH
            else:
                count = 0
                recommendation = None
                priority = AuditPriority.INFO

            results.append(AuditResult(
                title="SNMP Community Default Check",
                category=AuditCategory.DEVICE,
                description="Check if the SNMP community string is the default value ('public').",
                count=count,
                raw_output=f"Community: {device.snmp_community}",
                show_raw_output=True,
                priority=priority,
                recommendation=recommendation,
            ))
        
        return results

    def audit_software_version_compliance(self, var_bad: str) -> List[AuditResult]:
        """
        Check if the software version complies with security standards.

        Args:
            var_bad (str): The software version considered non-compliant.

        Returns:
            List[AuditResult]: A list containing audit results for all devices.
        """
        logging.debug("Auditing Software Version Compliance...")

        results = []  # Store results for all devices
        for device in self.parsed_config.devices:
            if device.software_version == var_bad:
                count = 1
                recommendation = "Update to the latest version!"
                priority = AuditPriority.HIGH
            else:
                count = 0
                recommendation = None
                priority = AuditPriority.INFO

            results.append(AuditResult(
                title="Software Version Compliance",
                category=AuditCategory.DEVICE,
                description="Audit software versions for compliance with vendor standards.",
                count=count,
                raw_output=f"Version: {device.software_version}",
                show_raw_output=True,
                priority=priority,
                recommendation=recommendation,
            ))

        return results
