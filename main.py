import argparse
import logging
import os
from datetime import datetime

from firewall_analyzer.orchestrator.cisco_orchestrator import CiscoOrchestrator
from firewall_analyzer.orchestrator.palotalto_orchestrator import PaloAltoOrchestrator
from firewall_analyzer.orchestrator.fortinet_orchestrator import FortinetOrchestrator
from firewall_analyzer.parser.cisco.cisco_asa_parser import CiscoASAParser
from firewall_analyzer.parser.paloalto.paloalto_panos_parser import PaloAltoPANOSParser
from firewall_analyzer.parser.fortinet.fortinet_fortigate_parser import FortinetFortigateParser
from firewall_analyzer.reporter.excel_reporter import ExcelReporter
from firewall_analyzer.reporter.html_reporter import HTMLReporter
from logging_config import setup_logging
from datetime import datetime

PALOALTO = {'paloalto': ['panos']}
CISCO = {'cisco': ['asa', 'ios']}
FORTINET = {"fortinet": ["fortios"]}

# Populate list of valid platforms
VENDOR_LIST = [PALOALTO, CISCO, FORTINET]
PLATFORMS = []

for vendor in VENDOR_LIST:
    for vendorkey, vendorlist in vendor.items():
        for vendorvalue in vendorlist:
            PLATFORMS.append(f'{vendorkey}.{vendorvalue}')

EXCEL = "excel"
HTML = "html"
REPORT_TYPES = [EXCEL, HTML]

def setup_argparse() -> argparse.Namespace:
    """Setup and parse command-line arguments."""
    parser = argparse.ArgumentParser(description="Script to audit a given FW config.")
    parser.add_argument(
        "-i",
        "--input",
        action="store",
        dest="inputfile",
        type=str,
        nargs="+",  # One or more arguments
        help="Path and filename to input the data.",
        required=True,
    )
    parser.add_argument(
        "-r",
        "--report",
        action="store",
        dest="report_type",
        type=str,
        choices=REPORT_TYPES,
        help="Report type (excel, html).",
        required=True,
    )
    parser.add_argument(
        "-p",
        "--platform",
        action="store",
        dest="platform",
        type=str,
        choices=PLATFORMS,
        help="Platform to use for the audit (e.g., paloalto.panos, fortinet.fortios, cisco.asa).",
        required=True,
    )
    parser.add_argument(
        "--output",  # New argument for output file path
        action="store",
        dest="output",
        type=str,
        help="Path for saving the report (optional). If not provided, a default filename will be used.",
    )
    return parser.parse_args()

def main():
    setup_logging()
    args = setup_argparse()
    logging.info(f"Input file: {args.inputfile}")
    logging.info(f"Platform: {args.platform}")
    logging.info(f"Report type: {args.report_type}")

    # Parse the input files
    if args.platform.split('.')[0] == list(PALOALTO.keys())[0]:
        for paloaltovalues in list(PALOALTO.values())[0]:
            if args.platform.split('.')[-1] == paloaltovalues:
                parser = PaloAltoPANOSParser(args.inputfile)
    elif args.platform.split('.')[0] == list(CISCO.keys())[0]:
        for ciscovalues in list(CISCO.values())[0]:
            if args.platform.split('.')[-1] == ciscovalues:
                parser = CiscoASAParser(args.inputfile)
    elif args.platform.split('.')[0] == list(FORTINET.keys())[0]:
        for fortinetvalues in list(FORTINET.values())[0]:
            if args.platform.split('.')[-1] == fortinetvalues:
                parser = FortinetFortigateParser(args.inputfile)

    parsed_config = parser.parse_all()

    current_time = datetime.now().strftime("%Y%m%d_%H%M")
    input_filename = os.path.splitext(os.path.basename(args.inputfile[0] if isinstance(args.inputfile, list) else args.inputfile))[0]

    # Generate custom report name
    report_name = f"{input_filename}_{current_time}_report"  # Set report name with input filename and timestamp

    # Audit the configuration using orchestrator based on platform
    if args.platform.split('.')[0] == list(PALOALTO.keys())[0]:
        orchistrator = PaloAltoOrchestrator(parsed_config)
    elif args.platform.split('.')[0] == list(CISCO.keys())[0]:
        orchistrator = CiscoOrchestrator(parsed_config)
    elif args.platform.split('.')[0] == list(FORTINET.keys())[0]:
        orchistrator = FortinetOrchestrator(parsed_config)      

    findings = orchistrator.run()

    # Generate the report
    output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'report_output')
    # Ensure the directory exists or create it
    os.makedirs(output_dir, exist_ok=True)

    # If --output argument is provided, use that path
    if args.output:
        output_file = os.path.join(output_dir, args.output)
    else:
        output_file = output_dir  # Default to using the generated report_name

    # Generate report based on requested format
    if args.report_type == HTML:
        reporter = HTMLReporter(findings, parsed_config, output_file, report_name)
    elif args.report_type == EXCEL:
        reporter = ExcelReporter(findings, parsed_config, output_file, report_name)
    
    reporter.generate_report()

if __name__ == "__main__":
    main()
