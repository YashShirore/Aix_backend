import logging
from firewall_analyzer.auditor.address_auditor import AddressAuditor
from firewall_analyzer.auditor.nat_auditor import NatAuditor
from firewall_analyzer.auditor.rule_auditor import RuleAuditor
from firewall_analyzer.auditor.service_auditor import ServiceAuditor
from firewall_analyzer.auditor.device_auditor import DeviceAuditor
from firewall_analyzer.orchestrator.base import BaseOrchestrator


logging.basicConfig(level=logging.DEBUG)


class CiscoOrchestrator(BaseOrchestrator):
    """Class for orchestrating the Cisco audit process."""

    def _load_address_audits(self):
        address_auditor = AddressAuditor(self.parsed_config)
        self.checks_to_run.extend([
            (address_auditor.audit_number_of_address_objects, {}),
            (address_auditor.audit_address_objects_not_in_use, {}),
            (address_auditor.audit_unique_addresses, {}),
        ])

    def _load_service_audits(self):
        service_auditor = ServiceAuditor(self.parsed_config)
        self.checks_to_run.extend([
            (service_auditor.audit_number_of_service_objects, {}),
            (service_auditor.audit_duplicate_service_objects, {}),
        ])

    def _load_device_audits(self):
        device_auditor = DeviceAuditor(self.parsed_config)
        self.checks_to_run.extend([
            (device_auditor.audit_snmp_default_community, {}),
        ])

    def _load_rule_audits(self):
        rule_auditor = RuleAuditor(self.parsed_config)
        self.checks_to_run.extend([
            (rule_auditor.audit_number_of_security_rules, {}),
            (rule_auditor.audit_rules_with_insecure_services, {}),
        ])

    def _load_nat_audits(self):
        nat_auditor = NatAuditor(self.parsed_config)
        self.checks_to_run.extend([
            (nat_auditor.audit_number_of_nat_rules, {}),
            (nat_auditor.audit_duplicate_nat_rules, {}),
        ])

    def _load_audits(self):
        """Load all audits for Cisco configurations."""
        self._load_address_audits()
        self._load_service_audits()
        self._load_device_audits()
        self._load_rule_audits()
        self._load_nat_audits()
