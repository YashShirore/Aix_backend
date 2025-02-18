import datetime
import logging
from typing import Any, List

import pandas as pd

from firewall_analyzer.models.audit_result_models import AuditResult
from firewall_analyzer.models.firewall_models import FirewallConfiguration

logging.basicConfig(level=logging.DEBUG)


class BaseReporter:
    """
    Base class for generating different types of reports.
    """

    def __init__(self, findings: List[AuditResult], parsed_config: FirewallConfiguration):
        """
        Initialize the BaseReporter class.

        Args:
            findings (List[AuditResult]): A list of findings to include in the report.
            parsed_config (FirewallConfiguration): Configuration settings for the report.
        """
        self.findings = findings
        self.parsed_config = parsed_config
        self.fname_prepend = f"report_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}"
        self.output_dir: str = "report_output"

    def generate_report(self) -> None:
        """
        Generate the report. This method should be implemented by subclasses.
        """
        raise NotImplementedError("Subclasses should implement this method.")