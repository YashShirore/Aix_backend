import logging
import os
from typing import Any, List
import pandas as pd
from firewall_analyzer.models.audit_result_models import AuditResult
from firewall_analyzer.reporter.base import BaseReporter

logging.basicConfig(level=logging.DEBUG)

class ExcelReporter(BaseReporter):
    """Class for generating Excel reports."""

    def __init__(self, findings: List[AuditResult], parsed_config: Any, output_dir: str, fname_prepend: str) -> None:
        """
        Initialize the ExcelReporter with findings, parsed configuration, output directory, and file name prefix.

        Args:
            findings: List of audit results to report.
            parsed_config: The parsed firewall configuration.
            output_dir: Directory where the report will be saved.
            fname_prepend: Prefix for the output file name.
        """
        self.findings = findings
        self.parsed_config = parsed_config
        self.output_dir = output_dir
        self.fname_prepend = fname_prepend

    def generate_report(self) -> None:
        """Generate and write the audit report to an XLSX file."""
        logging.debug("Generating XLSX report...")

        # Ensure the output file name is properly constructed
        fname = f"{self.fname_prepend}.xlsx"
        output_file = os.path.join(self.output_dir, fname)  # Correctly join the output path and filename

        try:
            # Ensure the directory exists
            os.makedirs(self.output_dir, exist_ok=True)

            # Create Excel writer with openpyxl engine
            with pd.ExcelWriter(output_file, engine="openpyxl") as writer:
                findings_data_list = []
                # Loop through findings and append the relevant information
                for data in self.findings:
                    if (
                        hasattr(data, "title")
                        and hasattr(data, "category")
                        and hasattr(data, "count")
                        and hasattr(data, "priority")
                        and hasattr(data, "description")
                    ):
                        findings_data_list.append(
                            {
                                "Category": data.category.value,
                                "Title": data.title,
                                "Count": data.count,
                                "Priority": data.priority.value,
                                "Description": data.description,
                            }
                        )

                findings_df = pd.DataFrame(findings_data_list)

                # Write findings to the 'Findings' sheet if data is available
                if not findings_df.empty:
                    findings_df.to_excel(writer, sheet_name="Findings", index=False)

                    # Get the openpyxl workbook and sheet objects for further formatting
                    worksheet = writer.sheets["Findings"]

                    # Set the width of the columns for better readability
                    worksheet.column_dimensions["A"].width = 20
                    worksheet.column_dimensions["B"].width = 50
                    worksheet.column_dimensions["C"].width = 15
                    worksheet.column_dimensions["D"].width = 15
                    worksheet.column_dimensions["E"].width = 50

                # Write system device info to a separate sheet
                if self.parsed_config.devices is not None:
                    devices_info = self.parsed_config.system_info.get("devices", [])
                    devices_df = pd.DataFrame(devices_info)
                    if not devices_df.empty:
                        devices_df.to_excel(writer, sheet_name="Device info", index=False)

                # Handle detailed output for each finding
                for data in self.findings:
                    if getattr(data, "show_raw_output", False):
                        try:
                            if isinstance(data.raw_output, list):
                                detailed_output_df = pd.DataFrame(data.raw_output)
                            elif isinstance(data.raw_output, str):
                                # If raw_output is a string, convert it to a list
                                detailed_output_df = pd.DataFrame([{"Raw Output": data.raw_output}])
                            else:
                                detailed_output_df = pd.DataFrame([])  # Empty DataFrame if raw_output is not a valid type
                        except Exception as e:
                            logging.error(f"Error creating DataFrame for raw_output: {e}")
                            continue  # Skip this data point if it can't be processed

                        if not detailed_output_df.empty:
                            # Ensure sheet name doesn't exceed 31 characters
                            sheet_name = f"{data.category.value} {data.title.strip()}"[:31]
                            detailed_output_df.to_excel(writer, sheet_name=sheet_name, index=False)

            logging.info(f"XLSX report generated successfully: {output_file}")

        except Exception as e:
            logging.error(f"Failed to generate XLS report: {e}")
            raise  # Re-raise the error after logging
