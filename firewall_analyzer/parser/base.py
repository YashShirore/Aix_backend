import logging
from typing import List

from firewall_analyzer.models.firewall_models import FirewallConfiguration


class BaseParser:
    """
    Class for parsing firewall configuration files. The files are read and attributes are
    parsed into a FirewallConfiguration object.

    Attributes:
        input_files: List of file paths to parse.
        parsed_config: The FirewallConfiguration object to store parsed data.
    """

    def __init__(self, input_files: List[str]):
        """
        Initialize the parser with input files.

        Args:
            input_files (List[str]): List of file paths to parse.
        """
        self.parsed_config = FirewallConfiguration()
        self.input_files = input_files

    def parse_all(self) -> FirewallConfiguration:
        """
        Parse all the input files.

        This method should be overridden by subclasses to provide specific parsing logic.

        Returns:
            FirewallConfiguration: The parsed firewall configuration.
        """
        raise NotImplementedError("Subclasses should implement this method")
