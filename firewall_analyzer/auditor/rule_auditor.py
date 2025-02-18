import logging
import re
from datetime import datetime
from typing import Callable, Dict, List, Tuple

from netaddr import IPNetwork, IPRange

from firewall_analyzer.models.audit_result_models import (
    AuditCategory,
    AuditPriority,
    AuditResult,
    AuditGroup,
)
from firewall_analyzer.models.firewall_models import AddressObject, Rule

from .base import BaseAuditor


class RuleAuditor(BaseAuditor):
    """Class for performing security rule firewall checks."""

    def _rule_search(self, condition: Callable[[Rule], bool]) -> List[Tuple[str, Rule]]:
        """Search for common rules based on a given condition.
        Args:
            condition (Callable[[Rule], bool]): The condition to filter the rules.
        Returns:
            List[Tuple[str, Rule]]: A list of tuples containing the name and rule objects that match the condition.
        """
        matches = []
        for rule in self.parsed_config.security_rules:
            if condition(rule):
                matches.append((rule.name, rule))
        return matches

    def _find_duplicates_deep_compare(self, rules: List[Rule]) -> List[List[Rule]]:
        """Find duplicate security rules using deep comparison.

        Args:
            rules (List[Rule]): The list of security rules to search for duplicates.

        Returns:
            List[List[Rule]]: A list of lists containing the duplicate security rules.
        """

        def rule_hash(rule: Rule) -> int:
            """Generate a hash for a given security rule.

            Args:
                rule (Rule): The security rule to generate the hash for.

            Returns:
                int: The hash value for the security rule.
            """
            return hash(
                (
                    tuple(rule.from_zone),
                    tuple(rule.to_zone),
                    tuple(rule.source_address),
                    tuple(rule.destination_address),
                    tuple(rule.destination_service),
                    rule.action,
                    rule.description,
                    tuple(rule.applications),
                    tuple(rule.devices),
                )
            )

        count: Dict[int, List[Rule]] = {}

        for rule in rules:
            h = rule_hash(rule)
            if h in count:
                count[h].append(rule)
            else:
                count[h] = [rule]

        duplicates = [rule_list for rule_list in count.values() if len(rule_list) > 1]

        return duplicates

    def audit_number_of_security_rules(self, **kwargs) -> AuditResult:
        """Get number of security rules.

        Args:
            **kwargs: Keyword arguments to filter the security rules.

        Returns:
            AuditResult: The audit result containing the count of security rules.

        """
        logging.debug("Auditing security rules...")
        if kwargs:
            matches = self._find_matches(self.parsed_config.security_rules, kwargs)
            return AuditResult(
                title=f"Count {' '.join(list(kwargs.keys()))} is {' '.join(list(kwargs.values()))}",
                category=AuditCategory.RULES,
                description=f"This is the number of {' '.join(list(kwargs.keys()))} is {' '.join(list(kwargs.values()))} security rules found in the configuration.",
                raw_output=matches,
                count=len(matches),
                priority=AuditPriority.INFO,
            )

        return AuditResult(
            title="Count total",
            category=AuditCategory.RULES,
            description="This is the number of security rules found in the configuration.",
            count=len(self.parsed_config.security_rules),
            priority=AuditPriority.INFO,
            show_raw_output=False,
        )

    def audit_number_of_security_rules_for_device_or_vsys(
        self, device_name, vsys_name=None
    ) -> AuditResult:
        """Get facts for security rules for a given device or vsys.

        Args:
            device_name (str): The name of the device.
            vsys_name (str, optional): The name of the vsys. Defaults to None.

        Returns:
            AuditResult: The audit result containing the count of security rules.

        """
        logging.debug("Auditing security rules for a given device or vsys...")
        matches = set()
        for rule in self.parsed_config.security_rules:
            for device_id, vsys_id in rule.devices:
                if device_id == device_name:
                    if vsys_name is None:
                        matches.add(rule.name)
                    else:
                        if vsys_name == vsys_id:
                            matches.add(rule.name)
        title = "Count "

        # convert the device id to a device name
        for device in self.parsed_config.devices:
            if device.id == device_name and device.hostname:
                device_name = device.hostname
                if vsys_name is not None:
                    for vsys_id, display_name in device.vsys_display_name.items():
                        if vsys_id == vsys_name:
                            vsys_name = display_name
                break
        title += f"{device_name}"

        if vsys_name is not None:
            title += f" {vsys_name}"
        return AuditResult(
            title=title,
            category=AuditCategory.RULES,
            description=f"This is the number of security rules found in the configuration for device:{device_name} vsys:{vsys_name}.",
            count=len(matches),
            raw_output=matches,
            priority=AuditPriority.INFO,
            show_raw_output=True,
        )

    def audit_duplicate_security_rules(self) -> AuditResult:
        """Audit duplicate security rules.

        This method audits the security rules for duplicates. It finds security rules that have the same source zone, destination zone, source address, destination address, destination port, and action. Having duplicate security rules can lead to operational complications, as modifications or deletions by engineers may not have the intended effect.

        Returns:
            AuditResult: An object containing the audit results.
        """
        logging.debug("Auditing duplicate security rules...")

        duplicates = self._find_duplicates(self.parsed_config.security_rules)

        if len(duplicates):
            recommendation = (
                "Review the duplicate security rules and remove any unnecessary rules."
            )
        else:
            recommendation = None

        return AuditResult(
            title="Duplicates total",
            category=AuditCategory.RULES,
            description="These are the security rules that have the same source zone, destination zone, source address, destination address, destination port, and action. Having duplicate security rules can lead to operational complications, as modifications or deletions by engineers may not have the intended effect.",
            count=len(duplicates),
            raw_output=duplicates,
            priority=AuditPriority.HIGH,
            show_raw_output=True,
            recommendation=recommendation,
            group=AuditGroup.DUPLICATES,
        )

    def audit_duplicate_security_rules_include_vsys(self) -> AuditResult:
        """Audit duplicate security rules with vsys.

        Returns:
            AuditResult: An object containing the audit results.
        """
        logging.debug("Auditing duplicate security rules with vsys...")
        duplicates = self._find_duplicates_deep_compare(
            self.parsed_config.security_rules
        )

        if len(duplicates):
            recommendation = (
                "Review the duplicate security rules and remove any unnecessary rules."
            )
        else:
            recommendation = None

        return AuditResult(
            title="    Duplicates match device and VSYS",
            category=AuditCategory.RULES,
            description="These are the security rules that have the same source zone, destination zone, source address, destination address, destination port, action, and vsys. Having duplicate security rules can lead to operational complications, as modifications or deletions by engineers may not have the intended effect.",
            count=len(duplicates),
            raw_output=duplicates,
            priority=AuditPriority.HIGH,
            show_raw_output=True,
            recommendation=recommendation,
            group=AuditGroup.DUPLICATES,
        )

    def audit_rules_with_insecure_services(self) -> AuditResult:
        """Audit insecure services.

        Returns:
            AuditResult: An object containing the audit results.
        """
        logging.debug("Auditing rules with insecure services...")
        insecure_protocols = {"tcp": ["23", "20", "21"]}  # Telnet and FTP ports
        matches = self._find_services(insecure_protocols)

        if len(matches):
            recommendation = "Review the security rules that contain insecure protocols to check if they are necessary. If not, remove them."
        else:
            recommendation = None

        return AuditResult(
            title="Contains Insecure Protocols",
            category=AuditCategory.RULES,
            description="These are the security rules that contain insecure protocols like Telnet and FTP. Using insecure services can lead to security vulnerabilities.",
            count=len(matches),
            raw_output=matches,
            priority=AuditPriority.MEDIUM,
            show_raw_output=True,
            recommendation=recommendation,
            group=AuditGroup.INSECURE_PROTOCOLS,
        )

    def audit_rules_with_insecure_services_telnet(self) -> AuditResult:
        """Audit insecure telnet service.

        Returns:
            AuditResult: An object containing the audit results.
        """
        logging.debug("Auditing rules with insecure services...")
        insecure_protocols = {"tcp": ["23"]}  # Telnet ports
        matches = self._find_services(insecure_protocols)
        if len(matches):
            recommendation = "Review the security rules that contain insecure protocols to check if they are necessary. If not, remove them."
        else:
            recommendation = None
        return AuditResult(
            title="Contains Insecure Protocol Telnet",
            category=AuditCategory.RULES,
            description="These are the security rules that contain insecure protocol Telnet. Using insecure services can lead to security vulnerabilities.",
            count=len(matches),
            raw_output=matches,
            priority=AuditPriority.MEDIUM,
            show_raw_output=True,
            recommendation=recommendation,
            group=AuditGroup.INSECURE_PROTOCOLS,
        )

    def audit_rules_with_insecure_services_ftp(self) -> AuditResult:
        """Audit insecure services.

        Returns:
            AuditResult: An object containing the audit results.
        """
        logging.debug("Auditing rules with insecure services...")
        insecure_protocols = {"tcp": ["20", "21"]}  # Telnet ports
        matches = self._find_services(insecure_protocols)
        if len(matches):
            recommendation = "Review the security rules that contain insecure protocols to check if they are necessary. If not, remove them."
        else:
            recommendation = None
        return AuditResult(
            title="Contains Insecure Protocol FTP",
            category=AuditCategory.RULES,
            description="These are the security rules that contain insecure protocol FTP. Using insecure services can lead to security vulnerabilities.",
            count=len(matches),
            raw_output=matches,
            priority=AuditPriority.MEDIUM,
            show_raw_output=True,
            recommendation=recommendation,
            group=AuditGroup.INSECURE_PROTOCOLS,
        )

    def audit_rules_with_insecure_services_http(self) -> AuditResult:
        """Audit insecure services.

        Returns:
            AuditResult: An object containing the audit results.
        """
        logging.debug("Auditing rules with insecure services...")
        insecure_protocols = {"tcp": ["80", "8080"]}  # http ports
        matches = self._find_services(insecure_protocols)
        if len(matches):
            recommendation = "Review the security rules that contain insecure protocols to check if they are necessary. If not, remove them."
        else:
            recommendation = None
        return AuditResult(
            title="Contains Insecure Protocol HTTP",
            category=AuditCategory.RULES,
            description="These are the security rules that contain insecure protocol HTTP. Using insecure services can lead to security vulnerabilities.",
            count=len(matches),
            raw_output=matches,
            priority=AuditPriority.MEDIUM,
            show_raw_output=True,
            recommendation=recommendation,
            group=AuditGroup.INSECURE_PROTOCOLS,
        )

    def _find_services(self, protocols):
        service_objects = []

        # Find all service objects containing the given protocols
        for service in self.parsed_config.service_objects:
            if service.protocol in protocols:
                if service.port in protocols[service.protocol]:
                    service_objects.append(service.name)

        condition = lambda rule: any(
            service in service_objects for service in rule.destination_service
        )
        matches = self._rule_search(condition)
        return matches

    def audit_ip_any_any_rules(self) -> AuditResult:
        """Audit IP Any Any Rules.

        Returns:
            AuditResult: An object containing the audit results.
        """
        logging.debug("Auditing IP Any Any rules...")
        condition = (
            lambda rule: "any" in rule.source_address
            and "any" in rule.destination_address
            and rule.action == "allow"
        )
        matches = self._rule_search(condition)
        if len(matches):
            recommendation = "Review the security rules to check if they are necessary or if they can be more resticted."
        else:
            recommendation = None

        return AuditResult(
            title="IP Any Any",
            category=AuditCategory.RULES,
            description="These are the security rules that allow any source and destination IP addresses. This can lead to security vulnerabilities.",
            count=len(matches),
            raw_output=matches,
            priority=AuditPriority.HIGH,
            show_raw_output=True,
            recommendation=recommendation,
            group=AuditGroup.OPEN_RULES,
        )

    def audit_rules_with_allow(self) -> AuditResult:
        """Audit rules with permit action.

        Returns:
            AuditResult: An object containing the audit results.
        """
        logging.debug("Auditing rules with permit action...")
        condition = lambda rule: rule.action == "allow"
        matches = self._rule_search(condition)
        if len(matches):
            recommendation = "Review the security rules to check if they are necessary or if they can be more resticted."
        else:
            recommendation = None
        return AuditResult(
            title="Permit Action",
            category=AuditCategory.RULES,
            description="These are the security rules that have a permit action. Permitting all traffic can lead to security vulnerabilities.",
            count=len(matches),
            raw_output=matches,
            priority=AuditPriority.INFO,
            show_raw_output=False,
            recommendation=recommendation,
        )

    def audit_rules_with_deny(self) -> AuditResult:
        """Audit rules with deny action.

        Returns:
            AuditResult: An object containing the audit results.
        """
        logging.debug("Auditing rules with deny action...")
        condition = lambda rule: rule.action == "deny"
        matches = self._rule_search(condition)

        return AuditResult(
            title="Deny Action",
            category=AuditCategory.RULES,
            description="These are the security rules that have a deny action.",
            count=len(matches),
            raw_output=matches,
            priority=AuditPriority.INFO,
            show_raw_output=False,
        )

    def audit_rules_with_drop(self) -> AuditResult:
        """Audit rules with drop action.

        Returns:
            AuditResult: An object containing the audit results.
        """
        logging.debug("Auditing rules with drop action...")
        condition = lambda rule: rule.action == "drop"
        matches = self._rule_search(condition)

        return AuditResult(
            title="Drop Action",
            category=AuditCategory.RULES,
            description="These are the security rules that have a drop action.",
            count=len(matches),
            raw_output=matches,
            priority=AuditPriority.INFO,
            show_raw_output=False,
        )

    def audit_rules_explicit_drop(self) -> AuditResult:
        """Checks if there is an explicit deny action as the last rule.

        Returns:
            AuditResult: An object containing the audit results.
        """
        logging.debug("Auditing rules with explicit deny action...")
        if (
            self.parsed_config.security_rules and 
            self.parsed_config.security_rules[-1].action == "drop"
            and self.parsed_config.security_rules[-1].log_setting
        ):
            count = "Yes"
        else:
            count = "No"

        if count == "No":
            recommendation = "Ensure that the rulebase contains an explicit deny and is being logged."
        else:
            recommendation = None

        return AuditResult(
            title="Explicit Deny with Log Setting",
            category=AuditCategory.RULES,
            description="This checks that the last rule is a drop action and also contains a log setting.",
            count=count,
            raw_output=None,
            priority=AuditPriority.HIGH,
            show_raw_output=False,
            recommendation=recommendation,
        )

    def audit_number_of_application_rules(self) -> AuditResult:
        """Audit IP Any Any and Application Any Rules.

        Returns:
            AuditResult: An object containing the audit results.
        """
        logging.debug("Auditing Count application rules...")

        condition = lambda rule: "any" not in rule.applications
        matches = self._rule_search(condition)

        return AuditResult(
            title="Contains an app service",
            category=AuditCategory.RULES,
            description="These are the security rules that contain an application.",
            count=len(matches),
            raw_output=matches,
            priority=AuditPriority.INFO,
            show_raw_output=True,
        )

    def audit_number_of_application_rules_using_non_default_service(
        self,
    ) -> AuditResult:
        """Audit IP Any Any and Application Any Rules.

        Returns:
            AuditResult: An object containing the audit results.
        """
        logging.debug("Auditing Count of application rules...")

        condition = (
            lambda rule: "any" not in rule.applications
            and "application-default" not in rule.destination_service
        )
        matches = self._rule_search(condition)

        return AuditResult(
            title="Contains an app service missing default-application",
            category=AuditCategory.RULES,
            description="These are the security rules that contain an application but does not contain 'default-application' for destination service.",
            count=len(matches),
            raw_output=matches,
            priority=AuditPriority.MEDIUM,
            show_raw_output=True,
            group=AuditGroup.OPEN_RULES,
        )

    def audit_ip_any_source_rules(self) -> AuditResult:
        """Audit IP Any Source Rules.

        Returns:
            AuditResult: An object containing the audit results.
        """
        logging.debug("Auditing IP Any Source rules...")
        condition = (
            lambda rule: "any" in rule.source_address
            and rule.action == "allow"
            and "any" not in rule.destination_address
        )
        matches = self._rule_search(condition)
        if len(matches):
            recommendation = "Review the security rules to check if they are necessary or if they can be more resticted."
        else:
            recommendation = None

        return AuditResult(
            title="Src IP Any",
            category=AuditCategory.RULES,
            description="These are the security rules that allow any source IP address. Allowing any source IP address can lead to security vulnerabilities.",
            count=len(matches),
            raw_output=matches,
            priority=AuditPriority.MEDIUM,
            show_raw_output=True,
            recommendation=recommendation,
            group=AuditGroup.OPEN_RULES,
        )

    def audit_ip_any_destination_rules(self) -> AuditResult:
        """Audit IP Any Destination Rules.

        Returns:
            AuditResult: An object containing the audit results.
        """
        logging.debug("Auditing IP Any Destination rules...")
        condition = (
            lambda rule: "any" in rule.destination_address
            and rule.action == "allow"
            and "any" not in rule.source_address
        )
        matches = self._rule_search(condition)
        if len(matches):
            recommendation = "Review the security rules to check if they are necessary or if they can be more resticted."
        else:
            recommendation = None

        return AuditResult(
            title="Dest IP Any",
            category=AuditCategory.RULES,
            description="These are the security rules that allow any destination IP address. Allowing any destination IP address can lead to security vulnerabilities.",
            count=len(matches),
            raw_output=matches,
            priority=AuditPriority.HIGH,
            show_raw_output=True,
            recommendation=recommendation,
            group=AuditGroup.OPEN_RULES,
        )

    def audit_dest_protocol_any_rules(self) -> AuditResult:
        """Audit destination protocol any rules.

        Returns:
            AuditResult: An object containing the audit results.
        """
        logging.debug("Auditing destination protocol any rules...")
        condition = (
            lambda rule: "any" in rule.destination_service
            and "any" in rule.applications
            and rule.action == "allow"
        )
        matches = self._rule_search(condition)
        if len(matches) > 0:
            recommendation = "Review the security rules to check if they are necessary or if they can be more resticted."
        else:
            recommendation = None

        return AuditResult(
            title="Destination Protocol and Application is Any",
            category=AuditCategory.RULES,
            description="These are the security rules that allow any destination port and any application. Allowing any destination port can lead to security vulnerabilities.",
            count=len(matches),
            raw_output=matches,
            priority=AuditPriority.HIGH,
            show_raw_output=True,
            recommendation=recommendation,
            group=AuditGroup.OPEN_RULES,
        )

    def audit_rules_missing_description(self) -> AuditResult:
        """Audit rules without description.

        Returns:
            AuditResult: An object containing the audit results.
        """
        logging.debug("Auditing rules missing description...")
        condition = lambda rule: rule.description is None
        matches = self._rule_search(condition)
        if len(matches) > 0:
            recommendation = "Add a description to the security rules to help audit and understanding the purpose of the rule."
        else:
            recommendation = None

        return AuditResult(
            title="Description Missing",
            category=AuditCategory.RULES,
            description="These are the security rules that do not have a description. Providing a description can help in understanding the purpose of the rule and facilitates easier auditing.",
            count=len(matches),
            raw_output=matches,
            priority=AuditPriority.MEDIUM,
            show_raw_output=True,
            recommendation=recommendation,
        )

    def audit_overlapping_rules(self, include_devices=False) -> AuditResult:
        """Audit overlapping rules.

        Returns:
            AuditResult: An object containing the audit results.
        """
        logging.debug("Auditing overlapping rules...")

        overlapping_rules = self._find_overlapping_rules(
            include_devices=include_devices
        )
        if include_devices:
            title = "Overlapping rules"
            description = "These are the security rules that are a subset of another rule including devices. This can can lead to shadowed rules, ambiguity, and can lead to operational complications, as modifications or deletions by engineers may not have the intended effect."
        else:
            title = "Overlapping rules excluding devices"
            description = "These are the security rules that are a subset of another rule excluding devices. This can can lead to shadowed rules, ambiguity, and can lead to operational complications, as modifications or deletions by engineers may not have the intended effect."

        if len(overlapping_rules) > 0:
            recommendation = "Review the overlapping rules to check if they are necessary or if they can be removed."
        else:
            recommendation = None

        return AuditResult(
            title=title,
            category=AuditCategory.RULES,
            description=description,
            count=len(overlapping_rules),
            raw_output=overlapping_rules,
            priority=AuditPriority.HIGH,
            show_raw_output=True,
            recommendation=recommendation,
        )

    def _audit_rule_name_contains(self, keywords: List) -> List[Tuple[str, Rule]]:
        """Audit rules where the rule name contains a specific keyword.

        Args:
            keyword (List): The keywords to search for in rule names.

        Returns:
            matches (List[Tuple[str, Rule]]): A list of tuples containing the name and rule objects that match the condition.
        """
        logging.debug(f"Auditing rules with names containing '{keywords}'...")

        condition = lambda rule: any(
            keyword in rule.name.lower() for keyword in keywords
        )
        matches = self._rule_search(condition)
        return matches

    def audit_rule_name_contains_temporary(self) -> AuditResult:
        """Audit temporary rules by checking if the rule name contains temporary keywords.

        Returns:
            AuditResult: An object containing the audit results.
        """
        logging.debug("Auditing temporary rules...")
        keywords = [
            "tmp",
            "temp",
            "trial",
            "example",
            "sandbox",
            "tst",
            "demo",
            "draft",
            "pilot",
            "debug",
            "old",
            "copy",
            "duplicate",
        ]

        matches = self._audit_rule_name_contains(keywords)
        if len(matches) > 0:
            recommendation = (
                "Review the security rules to check if they should be removed"
            )
        else:
            recommendation = None

        return AuditResult(
            title="Name contains temporary keywords",
            category=AuditCategory.RULES,
            description=f"These are the security rules that contain names like {','.join(keywords)} implying a temporary rule. Temporary rules that have not been removed can lead to security vulnerabilities.",
            count=len(matches),
            raw_output=matches,
            priority=AuditPriority.MEDIUM,
            show_raw_output=True,
            recommendation=recommendation,
            group=AuditGroup.TEMP_KEYWORDS,
        )

    def audit_rule_name_contains_test(self) -> AuditResult:
        """Audit temporary rules.

        Returns:
            AuditResult: An object containing the audit results.
        """
        logging.debug("Auditing temporary rules...")
        keywords = [
            "test",
        ]

        matches = self._audit_rule_name_contains(keywords)
        if len(matches) > 0:
            recommendation = (
                "Review the security rules to check if they should be removed"
            )
        else:
            recommendation = None

        return AuditResult(
            title="Name contains test keyword",
            category=AuditCategory.RULES,
            description=f"These are the security rules that contain names like {','.join(keywords)} implying a temporary rule. Temporary rules that have not been removed can lead to security vulnerabilities.",
            count=len(matches),
            raw_output=matches,
            priority=AuditPriority.LOW,
            show_raw_output=True,
            recommendation=recommendation,
            group=AuditGroup.TEMP_KEYWORDS,
        )

    def audit_rule_name_contains_poc(self) -> AuditResult:
        """Audit temporary rules.

        Returns:
            AuditResult: An object containing the audit results.
        """
        logging.debug("Auditing temporary rules...")
        keywords = [
            "poc",
        ]

        matches = self._audit_rule_name_contains(keywords)

        if len(matches) > 0:
            recommendation = (
                "Review the security rules to check if they should be removed"
            )
        else:
            recommendation = None
        return AuditResult(
            title="Name contains poc keyword",
            category=AuditCategory.RULES,
            description=f"These are the security rules that contain names like {','.join(keywords)} implying a temporary rule. Temporary rules that have not been removed can lead to security vulnerabilities.",
            count=len(matches),
            raw_output=matches,
            priority=AuditPriority.LOW,
            show_raw_output=True,
            recommendation=recommendation,
            group=AuditGroup.TEMP_KEYWORDS,
        )

    def audit_rules_missing_log_settings(self) -> AuditResult:
        """Audit rules without log settings.

        Returns:
            AuditResult: An object containing the audit results.
        """
        logging.debug("Auditing rules missing log settings...")
        condition = lambda rule: rule.log_setting is None
        matches = self._rule_search(condition)

        if len(matches) > 0:
            recommendation = "Ensure that all security rules have a log setting to monitor and audit network traffic."
        else:
            recommendation = None
        return AuditResult(
            title="Logging Missing",
            category=AuditCategory.RULES,
            description="These are the security rules that do not have a log setting. Logging is important for monitoring and auditing network traffic.",
            count=len(matches),
            raw_output=matches,
            priority=AuditPriority.MEDIUM,
            show_raw_output=True,
            recommendation=recommendation,
        )

    def audit_rules_with_tags(self) -> AuditResult:
        """Audit rules with tags.

        Returns:
            AuditResult: An object containing the audit results.
        """
        logging.debug("Auditing rules with tags...")
        condition = lambda rule: rule.tags
        matches = self._rule_search(condition)

        return AuditResult(
            title="Count Tags",
            category=AuditCategory.RULES,
            description="These are the security rules that contain tags. Using tags can help in identifying and grouping rules.",
            count=len(matches),
            raw_output=matches,
            priority=AuditPriority.INFO,
            show_raw_output=True,
        )

    def _find_overlapping_rules(self, include_devices=False) -> List[Tuple[str, str]]:
        """Find overlapping security rules.

        Returns:
            List[Tuple[str, str]]: A list of tuples representing the overlapping rule pairs.
        """
        overlapping_rules = []

        # Iterate through each pair of rules
        for i, rule1 in enumerate(self.parsed_config.security_rules):
            for j, rule2 in enumerate(self.parsed_config.security_rules):
                if i >= j:  # Avoid checking the same pair twice or a rule with itself
                    continue

                # Compare rule1 with rule2
                if self._is_subset(rule1, rule2, include_devices) or self._is_subset(
                    rule2, rule1, include_devices
                ):
                    overlapping_rules.append((rule1, rule2))

        return overlapping_rules

    def _is_subset(self, rule1: Rule, rule2: Rule, include_devices=False) -> bool:
        """Check if all attributes of rule1 are subsets of the corresponding attributes in rule2
        and at least one attribute of rule1 is a proper subset (i.e., rule2 contains additional items in that attribute)

        Args:
            rule1 (RuleTerm): The first security rule term.
            rule2 (RuleTerm): The second security rule term.

        Returns:
            bool: True if rule1 is a subset of rule2, False otherwise.
        """

        if include_devices:
            attribues = [
                "from_zone",
                "to_zone",
                "source_address",
                "destination_address",
                "destination_service",
                "devices",
            ]
        else:
            attribues = [
                "from_zone",
                "to_zone",
                "source_address",
                "destination_address",
                "destination_service",
            ]
        subset_condition = all(
            set(getattr(rule1, attr)) <= set(getattr(rule2, attr)) for attr in attribues
        )
        proper_subset_condition = any(
            set(getattr(rule1, attr)) < set(getattr(rule2, attr)) for attr in attribues
        )

        return subset_condition and proper_subset_condition

    def audit_rules_containing_rfc1918(self) -> AuditResult:
        """Audit rules containing RFC1918 addresses.

        Returns:
            AuditResult: An object containing the audit results.
        """
        logging.debug("Auditing rules containing RFC1918 addresses...")
        condition = lambda rule: self._find_rfc1918_in_rule(rule)
        matches = self._rule_search(condition)

        return AuditResult(
            title="Contains RFC1918 Address",
            category=AuditCategory.RULES,
            description="These are the security rules that contain RFC1918 addresses in either the source or destination.",
            count=len(matches),
            raw_output=matches,
            priority=AuditPriority.INFO,
            show_raw_output=True,
        )

    def _find_rfc1918_in_rule(self, rule: Rule) -> bool:
        """Check if the given rule contains RFC1918 addresses.

        Args:
            rule (Rule): The security rule.

        Returns:
            bool: True if the rule contains RFC1918 addresses, False otherwise.
        """
        for address in rule.source_address + rule.destination_address:
            address_objects = self._extract_address_objects_from_address_name(address)
            for obj in address_objects:
                if self._has_rfc1918_address(obj):
                    return True
        return False

    def _extract_address_objects_from_address_name(
        self, address_name
    ) -> List[AddressObject]:
        address_objects = []
        found = False
        for address in self.parsed_config.address_objects:
            if address.name == address_name:
                found = True
                address_objects.append(address)
        for address_group in self.parsed_config.address_groups:
            if address_group.name == address_name:
                found = True
                for member in address_group.members:
                    address_objects.extend(
                        self._extract_address_objects_from_address_name(member)
                    )
        if not found:
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", address_name):
                address_object = AddressObject(name=address_name, netmask=address_name)
                address_objects.append(address_object)
        return address_objects

    def audit_rules_containing_public_addresses(self) -> AuditResult:
        """Audit rules containing public addresses.

        Returns:
            AuditResult: An object containing the audit results.
        """
        logging.debug("Auditing rules containing public addresses...")
        condition = lambda rule: self._find_public_ip_in_rule(rule)
        matches = self._rule_search(condition)

        return AuditResult(
            title="Contains Public Address",
            category=AuditCategory.RULES,
            description="These are the security rules that contain public addresses in either the source or destination.",
            count=len(matches),
            raw_output=matches,
            priority=AuditPriority.INFO,
            show_raw_output=True,
        )

    def _find_public_ip_in_rule(self, rule: Rule) -> bool:
        """Check if the given rule contains a public IP address.

        Args:
            rule (Rule): The security rule.

        Returns:
            bool: True if the rule contains a public IP address, False otherwise.
        """
        for address in rule.source_address + rule.destination_address:
            address_objects = self._extract_address_objects_from_address_name(address)
            for obj in address_objects:
                if self._has_public_address(obj):
                    return True
        return False

    def _has_public_address(self, address: AddressObject) -> bool:
        """Check if the given address contains a public address."""

        if address.range:
            ip_range = IPRange(address.range.split("-")[0], address.range.split("-")[1])
            if not any(
                ip_range in rfc1918_range for rfc1918_range in self.rfc1918_ranges
            ):
                return True
        elif address.netmask:
            ip_network = IPNetwork(address.netmask)
            if not any(
                ip_network in rfc1918_range for rfc1918_range in self.rfc1918_ranges
            ):
                return True
        return False

    def audit_rules_that_are_disabled(self) -> AuditResult:
        """Audit rules that are disabled.

        Returns:
            AuditResult: An object containing the audit results.
        """
        logging.debug("Auditing disabled rules...")
        condition = lambda rule: rule.disabled
        matches = self._rule_search(condition)

        return AuditResult(
            title="Disabled Rules",
            category=AuditCategory.RULES,
            description="These are the security rules that are disabled.",
            count=len(matches),
            raw_output=matches,
            priority=AuditPriority.INFO,
            show_raw_output=True,
        )

    def audit_rules_with_dest_larger_than(self, number_of_hosts) -> AuditResult:
        """Audit rules with destination IP larger than a given number of hosts.

        Returns:
            AuditResult: An object containing the audit results.
        """
        logging.debug(
            f"Auditing rules with destination IP larger than {number_of_hosts}..."
        )
        condition = lambda rule: self._find_ip_with_hosts_greater_than(
            rule, number_of_hosts, "destination"
        )
        matches = self._rule_search(condition)

        if len(matches) > 0:
            recommendation = "Review the security rules to check if they are necessary or if they can be more resticted."
        else:
            recommendation = None

        return AuditResult(
            title=f"Dest Larger than {number_of_hosts} hosts",
            category=AuditCategory.RULES,
            description=f"These are the security rules that contain destination IP addresses larger than {number_of_hosts} hosts.",
            count=len(matches),
            raw_output=matches,
            priority=AuditPriority.INFO,
            show_raw_output=True,
            recommendation=recommendation,
        )

    def _find_ip_with_hosts_greater_than(
        self, rule: Rule, hosts_limit: int, address_type: str
    ) -> bool:
        """Find IP addresses in a rule with hosts greater than a given limit.
        Args:
            rule (Rule): The security rule.
            hosts_limit (int): The maximum number of hosts.
            address_type (str): The type of address (source or destination).
        Returns:
            bool: True if the rule contains IP addresses with hosts greater than the limit, False otherwise.
        """
        cache_key = (
            "rule_dest_num_of_hosts"
            if address_type == "destination"
            else "rule_src_num_of_hosts"
        )
        if cache_key not in self.cache:
            self.cache[cache_key] = {}
        if rule.name in self.cache[cache_key]:
            return self.cache[cache_key][rule.name] > hosts_limit

        hosts_num = 0
        addresses = (
            rule.destination_address
            if address_type == "destination"
            else rule.source_address
        )
        for address in addresses:
            address_objects = self._extract_address_objects_from_address_name(address)
            for obj in address_objects:
                hosts_num += obj.get_number_of_hosts()
        self.cache[cache_key][rule.name] = hosts_num
        return hosts_num > hosts_limit

    def audit_rules_with_source_larger_than(self, number_of_hosts) -> AuditResult:
        """Audit rules with IP larger than the given number of hosts.

        Returns:
            AuditResult: An object containing the audit results.
        """
        logging.debug(f"Auditing rules with source IP larger than {number_of_hosts}...")
        condition = lambda rule: self._find_ip_with_hosts_greater_than(
            rule, number_of_hosts, "source"
        )
        matches = self._rule_search(condition)

        if len(matches) > 0:
            recommendation = "Review the security rules to check if they are necessary or if they can be more resticted."
        else:
            recommendation = None

        return AuditResult(
            title=f"Src Larger than {number_of_hosts} hosts",
            category=AuditCategory.RULES,
            description=f"These are the security rules that contain source IP addresses larger than {number_of_hosts} hosts.",
            count=len(matches),
            raw_output=matches,
            priority=AuditPriority.INFO,
            show_raw_output=True,
            recommendation=recommendation,
        )

    def audit_top_services(self) -> AuditResult:
        # Get the top 10 service objects of service groups that are in the rules
        logging.debug("Auditing top services...")
        service_objects = {}
        for rule in self.parsed_config.security_rules:
            for service in rule.destination_service:
                service_objects[service] = service_objects.get(service, 0) + 1
        # Sort the service objects by the number of times they are used
        sorted_service_objects = sorted(
            service_objects.items(), key=lambda x: x[1], reverse=True
        )
        return AuditResult(
            title="Top Services",
            category=AuditCategory.RULES,
            description=f"The services sorted by the number of times they are used.",
            count="See worksheet",
            raw_output=sorted_service_objects,
            priority=AuditPriority.INFO,
            show_raw_output=True,
        )

    def audit_top_applications(self) -> AuditResult:
        # Get the top 10 application objects of application groups that are in the rules
        logging.debug("Auditing top applications...")
        application_objects = {}
        for rule in self.parsed_config.security_rules:
            for application in rule.applications:
                application_objects[application] = (
                    application_objects.get(application, 0) + 1
                )
        # Sort the application objects by the number of times they are used
        sorted_application_objects = sorted(
            application_objects.items(), key=lambda x: x[1], reverse=True
        )
        return AuditResult(
            title="Top Applications",
            category=AuditCategory.RULES,
            description=f"The applications sorted by the number of times they are used.",
            count="See worksheet",
            raw_output=sorted_application_objects,
            priority=AuditPriority.INFO,
            show_raw_output=True,
        )

    def _check_date_range_expiry(self, date_range_str):
        # Parse the date range string using datetime format
        try:
            start_str, end_str = date_range_str.split("-")
            end_date = datetime.strptime(end_str, "%Y/%m/%d@%H:%M")
        except ValueError:
            raise ValueError("Date range string is not in the expected format")
        current_date = datetime.now()
        return current_date - end_date

    def audit_schedules_expiry(self, max_days: int = 0) -> AuditResult:
        """
        Checks if any rules were tied to a schedule that has expired more than max_days in the past.

        Args:
            max_days (int): The maximum number of days for a schedule to be considered expired. Defaults to 0.

        Returns:
            AuditResult: An object containing the audit result.

        """
        logging.debug("Auditing schedules expiry...")
        matches = [
            (rule.name, rule, schedule)
            for rule in self.parsed_config.security_rules
            if rule.schedule
            for schedule in self.parsed_config.schedules
            if rule.schedule == schedule.name
            for member in schedule.members
            if self._is_schedule_expired(member, max_days)
        ]

        title = (
            f"Expired Schedules over {max_days} days"
            if max_days > 0
            else "Expired Schedules"
        )
        description = (
            f"These are the schedules that are expired over {max_days} days."
            if max_days > 0
            else "These are the schedules that are expired."
        )

        if len(matches) > 0:
            recommendation = "Remove the rule if it is no longer required."
        else:
            recommendation = None

        return AuditResult(
            title=title,
            category=AuditCategory.RULES,
            description=description,
            count=len(matches),
            raw_output=matches,
            priority=AuditPriority.MEDIUM,
            show_raw_output=True,
            recommendation=recommendation,
            group=AuditGroup.EXPIRED_SCHEDULES,
        )

    def _is_schedule_expired(self, date_range_str: str, max_days: int) -> bool:
        time_diff = self._check_date_range_expiry(date_range_str)
        return time_diff.days > max_days
