import logging
from typing import Any, List

from firewall_analyzer.auditor.address_auditor import AddressAuditor
from firewall_analyzer.auditor.nat_auditor import NatAuditor
from firewall_analyzer.auditor.rule_auditor import RuleAuditor
from firewall_analyzer.auditor.service_auditor import ServiceAuditor
from firewall_analyzer.auditor.device_auditor import DeviceAuditor
from firewall_analyzer.orchestrator.base import BaseOrchestrator

logging.basicConfig(level=logging.DEBUG)


class PaloAltoOrchestrator(BaseOrchestrator):
    """
    Class for orchestrating the Palo Alto audit process.

    This class defines which audit checks to execute. It calls the auditors and generates the findings.
    """

    PLATFORM = "paloalto"

    def _load_address_audits(self) -> None:
        """Load address audits and add them to the list of checks to run."""
        address_auditor = AddressAuditor(self.parsed_config)

        self.checks_to_run.extend(
            [
                (address_auditor.audit_number_of_address_objects, {}),
                (address_auditor.audit_address_objects_not_in_use, {}),
                (address_auditor.audit_unique_addresses, {}),
                (address_auditor.audit_duplicate_addresses_different_types, {}),
                (address_auditor.audit_duplicate_addresses, {}),
                (address_auditor.audit_duplicate_addresses_with_one_duplicate, {}),
                (address_auditor.audit_duplicate_addresses_with_two_duplicates, {}),
                (address_auditor.audit_duplicate_addresses_with_three_or_more_duplicates, {}),
                (address_auditor.audit_address_objects_missing_description, {}),
                (address_auditor.audit_mismatched_address_objects, {}),
                (address_auditor.audit_number_of_address_objects, {"tags": "merged"}),
                (address_auditor.audit_number_of_address_groups, {}),
                (address_auditor.audit_number_of_address_groups, {"scope": "shared"}),
                (address_auditor.audit_number_of_address_groups, {"scope": "device-group"}),
                (address_auditor.audit_duplicate_address_groups, {}),
                (address_auditor.audit_address_groups_not_in_use, {}),
                (address_auditor.audit_number_of_address_groups, {"tags": "merged"}),
                (address_auditor.audit_address_groups_missing_description, {}),
            ]
        )

    def _load_service_audits(self) -> None:
        """Load service audits and add them to the list of checks to run."""
        service_auditor = ServiceAuditor(self.parsed_config)

        self.checks_to_run.extend(
            [
                (service_auditor.audit_number_of_service_objects, {}),
                (service_auditor.audit_number_of_service_objects, {"scope":  "shared"}),
                (service_auditor.audit_number_of_service_objects, {"scope": "device-group"}),
                (service_auditor.audit_duplicate_service_objects, {}),
                (service_auditor.audit_service_objects_not_in_use, {}),
                (service_auditor.audit_mismatched_service_objects, {}),
                (service_auditor.audit_number_of_service_objects, {"tags": "merged"}),
                (service_auditor.audit_service_objects_missing_description, {}),
                (service_auditor.audit_number_of_service_groups, {}),
                (service_auditor.audit_number_of_service_groups, {"tags": "merged"}),
                (service_auditor.audit_number_of_service_groups, {"scope": "shared"}),
                (service_auditor.audit_number_of_service_groups, {"scope": "device-group"}),
                (service_auditor.audit_duplicate_service_groups, {}),
                (service_auditor.audit_service_groups_not_in_use, {}),
                (service_auditor.audit_service_groups_missing_description, {}),
            ]
        )

    def _load_rules_audits(self) -> None:
        """Load rule audits and add them to the list of checks to run."""
        rule_auditor = RuleAuditor(self.parsed_config)
        devices = self.parsed_config.system_info.get('devices')

        self.checks_to_run.extend(
            [
                (rule_auditor.audit_number_of_security_rules, {}),
                (rule_auditor.audit_number_of_security_rules, {"scope": "shared"}),
                (rule_auditor.audit_number_of_security_rules, {"scope": "device-group"}),
            ]
        )

        for device in self.parsed_config.devices:
            if device.vsys_ids:
                self.checks_to_run.append(
                    (
                        rule_auditor.audit_number_of_security_rules_for_device_or_vsys,
                        {"device_name": device.id},
                    )
                )
                for vsys in device.vsys_ids:
                    self.checks_to_run.append(
                        (
                            rule_auditor.audit_number_of_security_rules_for_device_or_vsys,
                            {"device_name": device.id, "vsys_name": vsys},
                        )
                    )

        self.checks_to_run.extend(
            [
                (rule_auditor.audit_duplicate_security_rules, {}),
                (rule_auditor.audit_duplicate_security_rules_include_vsys, {}),
#                (rule_auditor.audit_overlapping_rules, {"include_devices": True}),
#                (rule_auditor.audit_overlapping_rules, {"include_devices": False}),
                (rule_auditor.audit_rule_name_contains_temporary, {}),
                (rule_auditor.audit_rule_name_contains_test, {}),
                (rule_auditor.audit_rule_name_contains_poc, {}),
                (rule_auditor.audit_rules_missing_description, {}),
                (rule_auditor.audit_rules_missing_log_settings, {}),
                (rule_auditor.audit_dest_protocol_any_rules, {}),
                (rule_auditor.audit_rules_with_insecure_services_ftp, {}),
                (rule_auditor.audit_rules_with_insecure_services_telnet, {}),
                (rule_auditor.audit_rules_with_insecure_services_http, {}),
                (rule_auditor.audit_rules_with_allow, {}),
                (rule_auditor.audit_rules_with_drop, {}),
                (rule_auditor.audit_rules_with_deny, {}),
                (rule_auditor.audit_rules_explicit_drop, {}),
                (rule_auditor.audit_rules_with_tags, {}),
                (rule_auditor.audit_number_of_security_rules, {"tags": "merged"}),
                (rule_auditor.audit_number_of_application_rules, {}),
                (rule_auditor.audit_number_of_application_rules_using_non_default_service, {}),
#                (rule_auditor.audit_rules_containing_rfc1918, {}),
#                (rule_auditor.audit_rules_containing_public_addresses, {}),
                (rule_auditor.audit_rules_that_are_disabled, {}),
#                (
#                    rule_auditor.audit_rules_with_dest_larger_than,
#                    {"number_of_hosts": 1000},
#                ),
#                (
#                    rule_auditor.audit_rules_with_dest_larger_than,
#                    {"number_of_hosts": 10000},
#                ),
#                (
#                    rule_auditor.audit_rules_with_dest_larger_than,
#                    {"number_of_hosts": 100000},
#                ),
#                (
#                    rule_auditor.audit_rules_with_dest_larger_than,
#                    {"number_of_hosts": 1000000},
#                ),
#                (
#                    rule_auditor.audit_rules_with_dest_larger_than,
#                    {"number_of_hosts": 3000000},
#                ),
#                (rule_auditor.audit_ip_any_destination_rules, {}),
#                (
#                    rule_auditor.audit_rules_with_source_larger_than,
#                    {"number_of_hosts": 1000},
#                ),
#                (
#                    rule_auditor.audit_rules_with_source_larger_than,
#                    {"number_of_hosts": 10000},
#                ),
#                (
#                    rule_auditor.audit_rules_with_source_larger_than,
#                    {"number_of_hosts": 100000},
#                ),
#                (
#                    rule_auditor.audit_rules_with_source_larger_than,
#                    {"number_of_hosts": 1000000},
#                ),
#                (
#                    rule_auditor.audit_rules_with_source_larger_than,
#                    {"number_of_hosts": 3000000},
#                ),
                (rule_auditor.audit_ip_any_source_rules, {}),
                (rule_auditor.audit_ip_any_any_rules, {}),
                (rule_auditor.audit_top_services, {}),
                (rule_auditor.audit_top_applications, {}),
                (rule_auditor.audit_schedules_expiry, {}),
                (rule_auditor.audit_schedules_expiry, {"max_days": 180}),
            ]
        )

    def _load_nat_audits(self) -> None:
        """Load NAT audits and add them to the list of checks to run."""
        nat_auditor = NatAuditor(self.parsed_config)

        self.checks_to_run.extend(
            [
                (nat_auditor.audit_number_of_nat_rules, {}),
                (nat_auditor.audit_number_of_nat_rules, {"scope": "shared"}),
                (nat_auditor.audit_number_of_nat_rules, {"scope": "device-group"})

            ]
        )

        for device in self.parsed_config.devices:
            if "virtual_devices" in device:
                self.checks_to_run.append(
                    (
                        nat_auditor.audit_number_of_nat_rules_for_device_or_vsys,
                        {"device_name": device["id"]},
                    )
                )
                for vsys in device["virtual_devices"]:
                    self.checks_to_run.append(
                        (
                            nat_auditor.audit_number_of_nat_rules_for_device_or_vsys,
                            {"device_name": device["id"], "vsys_name": vsys},
                        )
                    )

        self.checks_to_run.extend(
            [
                (nat_auditor.audit_duplicate_nat_rules, {}),
                (nat_auditor.audit_rule_name_contains_temporary, {}),
                (nat_auditor.audit_rule_name_contains_test, {}),
                (nat_auditor.audit_rule_name_contains_poc, {}),
                (nat_auditor.audit_rules_missing_description, {}),
                (nat_auditor.audit_rules_that_are_disabled, {}),
                (nat_auditor.audit_overlapping_rules, {"include_devices": True}),
                (nat_auditor.audit_overlapping_rules, {"include_devices": False}),
                (nat_auditor.audit_nat_exact_match_rules, {}),
                (nat_auditor.audit_nat_subset_of_rules, {}),
            ]
        )

    def _load_device_audits(self) -> None:
        device_auditor = DeviceAuditor(self.parsed_config)
        self.checks_to_run.extend(
            [
                (device_auditor.audit_number_of_devices, {}),
            ]
        )

    def _load_audits(self) -> None:
        self._load_address_audits()
        self._load_service_audits()
        self._load_rules_audits()
        self._load_nat_audits()
        self._load_device_audits()
