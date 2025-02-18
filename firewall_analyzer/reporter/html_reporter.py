import logging
from typing import Any, List, Dict

import matplotlib.pyplot as plt
import pandas as pd
from jinja2 import Template
from pretty_html_table import build_table

from firewall_analyzer.models.audit_result_models import (
    AuditCategory,
    AuditPriority,
    AuditResult,
)
from firewall_analyzer.reporter.base import BaseReporter

logging.basicConfig(level=logging.DEBUG)


class HTMLReporter(BaseReporter):
    """Class for generating HTML reports."""

    template_file = "firewall_analyzer/reporter/report_template.html"

    def generate_report(self) -> None:
        """
        Generate the HTML report.

        Returns:
            None
        """
        logging.debug("Generating HTML report...")
        fname = f"{self.fname_prepend}.html"
        output_file = f"{self.output_dir}/{fname}"
        data = ""
        toc = """
        <div class="toc-container">
        <h2>Table of Contents</h2>
            <nav id="navbar-toc" class="navbar navbar-light bg-light">
            <nav class="nav nav-pills flex-column">
        """

        data += self._generate_intro_content()

        for category in AuditCategory:
            toc += f'<a class="nav-link" href="#{category.value}">{category.value}</a>'

            data += self._generate_category_content(category)

        toc += """
        </nav>
        </nav>
        </div>
        """

        data = toc + data

        try:
            with open(self.template_file, "r") as file:
                template_content = file.read()
            template = Template(template_content)
            populated_template = template.render(content=data)
            with open(output_file, "w") as file:
                file.write(populated_template)
            logging.info(f"HTML report generated at {output_file}")
        except IOError as e:
            logging.error(f"File operation failed: {e}")

    def _generate_category_content(self, category: AuditCategory) -> str:
        """
        Generate the content for a specific category in the HTML report.

        Args:
            category: The category of the audit checks.

        Returns:
            The generated content as a string.
        """
        data = f'<h2 id="{category.value}">{category.value}</h2>'

        # Get all the checks for the category
        checks = [d for d in self.findings if category == d.category]

        # Generate content for the checks that are NOT grouped together.
        # Ignore checks that are INFO priority
        for check in checks:
            if check.group is None and check.priority is not AuditPriority.INFO:
                data += self._generate_individual_check_content(check)

        # Generate content for the checks that are grouped together
        grouped_checks = self._group_checks_by_group(checks)
        for group, group_checks in grouped_checks.items():
            data += self._generate_group_check_content(group_checks, group)

        # Generate summary data
        data += self._generate_category_summary_content(category)
        return data

    def _group_checks_by_group(
        self, checks: List[AuditResult]
    ) -> Dict[AuditResult, List[AuditResult]]:
        """
        Group the audit checks by their group.

        Args:
            checks: The list of audit checks.

        Returns:
            A dictionary where the keys are the groups and the values are the list of checks in that group.
        """
        group_checks = {}
        for check in checks:
            if check.group:
                group_checks.setdefault(check.group, []).append(check)
        return group_checks

    def _generate_pretty_table(self, df: pd.DataFrame) -> str:
        """
        Generate a pretty HTML table from a pandas DataFrame.

        Args:
            df: The pandas DataFrame.

        Returns:
            The generated HTML table as a string.
        """
        html_table = build_table(
            df,
            "grey_light",
            font_size="13px",
            font_family="sans-serif",
            width_dict=["600px", "120px", "auto", "auto", "auto"],
        )
        html_table_with_class = html_table.replace(
            "<table",
            '<table class=MsoNormalTable border=0 cellspacing=0 cellpadding=0 style="border-collapse:collapse"',
        )
        return f'<div class="center-div">{html_table_with_class}</div>'

    def _generate_category_summary_content(self, category: AuditCategory) -> str:
        """
        Generate the summary content for a specific category in the HTML report.

        Args:
            category: The category of the audit checks.

        Returns:
            The generated summary content as a string.
        """
        data = f"<h4>Summary {category.value} data</h4>"
        table_data = []
        found = False
        for d in self.findings:
            if category == d.category:
                table_data.append(
                    {"Name": d.title, "Count": d.count, "Priority": d.priority.value}
                )
                found = True
        if not found:
            return ""
        df = pd.DataFrame(table_data)
        fname = self._generate_bar_graph(df, category.value)
        data += self._generate_pretty_table(df)
        data += f'<div class="center-div"><img src="{fname}" alt="Bar Graph"></div>'
        return data

    def _generate_individual_check_content(self, check: AuditResult) -> str:
        """
        Generate standard content for the HTML report.

        Args:
            check: The audit result object.

        Returns:
            The generated content as a string.
        """
        # Check if the check.count is an integer
        if not isinstance(check.count, int):
            return ""

        # get all the checks for the category
        data = f"<h3>{check.title}</h3>"
        data += check.description

        table_data = [
            {
                "Name": check.title,
                "Count": check.count,
                "Priority": check.priority.value,
            }
        ]
        df = pd.DataFrame(table_data)
        data += self._generate_pretty_table(df)

        data += f"<h4>Recomendations</h4>"
        data += f"<p>{check.recommendation}</p>"

        return data

    def _generate_group_check_content(
        self, checks: List[AuditResult], group: AuditCategory
    ) -> str:
        """
        Generate standard content for the HTML report.

        Args:
            checks: The list of audit checks.
            group: The category of the audit checks.

        Returns:
            The generated content as a string.
        """
        data = f"<h3>{group.value}</h3>"
        data += group.get_description()

        table_data = [{"Name": d.title, "Count": d.count} for d in checks]

        df = pd.DataFrame(table_data)
        data += self._generate_pretty_table(df)

        data += f"<h4>Recomendations</h4>"
        data += f"<p>{group.get_recommendation()}</p>"

        return data

    def _generate_bar_graph(self, df: pd.DataFrame, title: str) -> str:
        """
        Generate a bar graph from a pandas DataFrame.

        Args:
            df: The pandas DataFrame.
            title: The title of the bar graph.

        Returns:
            The filename of the saved bar graph image.
        """
        # Remove any rows with non-integer values
        df = df[df["Count"].apply(lambda x: str(x).isdigit())]
        fig, ax1 = plt.subplots(figsize=(5, 5))
        color = "tab:red"
        ax1.set_xlabel("Name")
        ax1.set_ylabel("Count")
        ax1.bar(df["Name"], df["Count"], color=color)
        ax1.tick_params(axis="y")
        plt.xticks(rotation=45, ha="right")
        ax1.set_axisbelow(True)
        ax1.grid(True, color="lightgray")
        plt.title(title)
        plt.tight_layout()
        # Save the bar graph as an image
        fname = f"{self.fname_prepend}_{title}.png"
        plt.savefig(f"{self.output_dir}/{fname}")
        return fname

    def _generate_intro_content(self):
        return """
    <div class="section">
        <h2>Introduction</h2>
        <div class="content" id="introduction">
            <p>The aim of the assessment is to analyse the Firewall configuration and compare the policy elements (address & service objects, security & NAT policy) with established best practices and good security practices.  The resulting report will identify items such as duplicate rules and objects, weak protocols, and poor security policy rules.  This report can be used as a basis for prioritising and implementing corrective workstreams within appropriate timelines.</p>
        </div>
    </div>
       """
