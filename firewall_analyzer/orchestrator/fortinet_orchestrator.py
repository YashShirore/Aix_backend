import logging

from firewall_analyzer.auditor.address_auditor import AddressAuditor
from firewall_analyzer.auditor.nat_auditor import NatAuditor
from firewall_analyzer.auditor.rule_auditor import RuleAuditor
from firewall_analyzer.auditor.service_auditor import ServiceAuditor
from firewall_analyzer.auditor.device_auditor import DeviceAuditor
from firewall_analyzer.orchestrator.base import BaseOrchestrator

logging.basicConfig(level=logging.DEBUG)

class FortinetOrchestrator(BaseOrchestrator):
    def _load_address_audits(self):
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
            ]
        )
    
    def _load_service_audits(self):
            """Load address audits and add them to the list of checks to run."""
            service_auditor = ServiceAuditor(self.parsed_config)
            self.checks_to_run.extend(
                [
                    (service_auditor.audit_number_of_service_groups, {}),
                    (service_auditor.audit_service_groups_missing_description, {}),
                    (service_auditor.audit_duplicate_service_groups, {}),
            ]
        )
    
    def _load_rule_audits(self) -> None:
        rule_auditor = RuleAuditor(self.parsed_config)
        #Fetch number_of_hosts from the parsed_config
        # number_of_hosts = self.parsed_config.get('number_of_hosts', 100)  # Set default if not found
        # number_of_hosts = self.parsed_config.get_number_of_hosts()
        # number_of_hosts = getattr(self.parsed_config, 'number_of_hosts', 100)
        self.checks_to_run.extend(
            [
                (rule_auditor.audit_number_of_security_rules, {}),
                #(rule_auditor.audit_number_of_security_rules_for_device_or_vsys, {}),
                (rule_auditor.audit_duplicate_security_rules, {}),
                (rule_auditor.audit_duplicate_security_rules_include_vsys, {}),
                (rule_auditor.audit_rules_with_insecure_services, {}),
                (rule_auditor.audit_rules_with_insecure_services_telnet, {}),
                (rule_auditor.audit_rules_with_insecure_services_ftp, {}),                
                (rule_auditor.audit_rules_with_insecure_services_http, {}),
                (rule_auditor.audit_ip_any_any_rules, {}),
                (rule_auditor.audit_rules_with_allow, {}),
                (rule_auditor.audit_rules_with_deny, {}),
                (rule_auditor.audit_rules_with_drop, {}),
                (rule_auditor.audit_rules_explicit_drop, {}),
                (rule_auditor.audit_number_of_application_rules, {}),
                (rule_auditor.audit_number_of_application_rules_using_non_default_service, {}),
                (rule_auditor.audit_ip_any_source_rules, {}),
                (rule_auditor.audit_ip_any_destination_rules, {}),
                (rule_auditor.audit_dest_protocol_any_rules, {}),
                (rule_auditor.audit_rules_missing_description, {}),
                (rule_auditor.audit_overlapping_rules, {}),
                (rule_auditor.audit_rule_name_contains_temporary, {}),
                (rule_auditor.audit_rule_name_contains_test, {}),
                (rule_auditor.audit_rule_name_contains_poc, {}),
                (rule_auditor.audit_rules_missing_log_settings, {}),
                (rule_auditor.audit_rules_with_tags, {}),
                (rule_auditor.audit_rules_containing_rfc1918, {}),
                (rule_auditor.audit_rules_containing_public_addresses, {}),
                (rule_auditor.audit_rules_that_are_disabled, {}),
                (rule_auditor.audit_rules_with_dest_larger_than, {}),
                (rule_auditor.audit_rules_with_source_larger_than, {}),
                (rule_auditor.audit_top_services, {}),
                (rule_auditor.audit_top_applications, {}),
                (rule_auditor.audit_schedules_expiry, {}),
            ]
        )


    def _load_audits(self) -> None:
        self._load_address_audits()
        self._load_service_audits()
        self._load_rule_audits()
        #self._load_nat_audits()
        #self._load_device_audits()