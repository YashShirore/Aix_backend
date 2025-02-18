import logging
from typing import Any, List, Union
from firewall_analyzer.models.audit_result_models import AuditResult
from firewall_analyzer.models.firewall_models import FirewallConfiguration


class BaseOrchestrator:
    """
    Base class for orchestrating the audit process.

    This class defines which audit checks to execute, calls the auditors, and generates the findings.
    """

    def __init__(self, parsed_config: FirewallConfiguration) -> None:
        """
        Initialize the BaseOrchestrator class.

        Args:
            parsed_config (FirewallConfiguration): The parsed configuration.
        """
        self.parsed_config: FirewallConfiguration = parsed_config
        self.checks_to_run = []  # List to hold the checks to be run
        self.findings: List[AuditResult] = []  # List to store the findings
        self._load_audits()

    def _load_audits(self) -> None:
        """Load the audit checks."""
        raise NotImplementedError("Subclasses should implement this method")

    def run(self) -> List[AuditResult]:
        """Run the audit checks and collect findings.

        Returns:
            List[AuditResult]: The list of audit results.
        """
        self.findings = []  # Reset findings before running audits
        for check, args in self.checks_to_run:
            result = check(**args)
            if isinstance(result, list):  # If result is a list of AuditResult
                self.findings.extend(result)  # Flatten the list into findings
            else:
                self.findings.append(result)  # Append single AuditResult directly

        logging.debug(f"Findings after running all checks: {self.findings}")
        return self.findings
