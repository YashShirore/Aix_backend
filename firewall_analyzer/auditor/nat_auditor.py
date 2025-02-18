import logging
from typing import Callable, List, Tuple

from firewall_analyzer.models.audit_result_models import (
    AuditCategory,
    AuditPriority,
    AuditResult,
    AuditGroup,
)
from firewall_analyzer.models.firewall_models import Nat, Rule

from .base import BaseAuditor


class NatAuditor(BaseAuditor):
    """Class for performing NAT firewall audit checks."""

    def _rule_search(self, condition: Callable[[Nat], bool]) -> List[Tuple[str, Rule]]:
        """Search for common rules based on a given condition.
        Args:
            condition (Callable[[Rule], bool]): The condition to filter the rules.
        Returns:
            List[Tuple[str, Rule]]: A list of tuples containing the name and rule objects that match the condition.
        """
        matches = []
        for rule in self.parsed_config.nat_rules:
            if condition(rule):
                matches.append((rule.name, rule))
        return matches

    def audit_number_of_nat_rules(self, **kwargs) -> AuditResult:
        """Audit the number of NAT rules.

        Args:
            **kwargs: Keyword arguments used to filter the NAT rules.

        Returns:
            AuditResult: An AuditResult object containing the audit result.

        Raises:
            None

        """
        logging.debug("Auditing security rules...")
        if kwargs:
            matches = self._find_matches(self.parsed_config.nat_rules, kwargs)
            return AuditResult(
                title=f"Count {' '.join(list(kwargs.keys()))} is {' '.join(list(kwargs.values()))}",
                category=AuditCategory.NAT,
                description=f"This is the number of {' '.join(list(kwargs.keys()))} is {' '.join(list(kwargs.values()))} NAT rules found in the configuration.",
                raw_output=matches,
                count=len(matches),
                priority=AuditPriority.INFO,
            )

        return AuditResult(
            title="Count total",
            category=AuditCategory.NAT,
            description="This is the number of NAT rules found in the configuration.",
            count=len(self.parsed_config.nat_rules),
            priority=AuditPriority.INFO,
            show_raw_output=False,
        )

    def audit_number_of_nat_rules_for_device_or_vsys(
        self, device_name, vsys_name=None
    ) -> AuditResult:
        """Get facts for security rules for a given device or vsys."""
        logging.debug("Auditing security rules for a given device or vsys...")
        matches = set()
        for rule in self.parsed_config.nat_rules:
            for device in rule.devices:
                if device == device_name:
                    if vsys_name is None:
                        matches.add(rule.name)
                    else:
                        for vsys in rule.devices[device]:
                            if vsys == vsys_name:
                                matches.add(rule.name)
        title = "Count "

        # convert the device id to a device name
        for item in self.parsed_config.system_info["devices"]:
            if item["id"] == device_name and "hostname" in item:
                device_name = item["hostname"]
                if vsys_name is not None:
                    for vsys_id, display_name in item["vsys display name"].items():
                        if vsys_id == vsys_name:
                            vsys_name = display_name
                break
        title += f"{device_name}"

        if vsys_name is not None:
            title += f" {vsys_name}"
        return AuditResult(
            title=title,
            category=AuditCategory.NAT,
            description=f"This is the number of nat rules found in the configuration for device:{device_name} vsys:{vsys_name}.",
            count=len(matches),
            raw_output=matches,
            priority=AuditPriority.INFO,
            show_raw_output=True,
        )

    def audit_duplicate_nat_rules(self) -> AuditResult:
        """Audit duplicate nat rules.

        This method audits the nat rules for duplicates based on various criteria such as source zone, destination zone,
        source address, destination address, destination port, translated address, etc. Duplicate nat rules can lead to
        operational complications as modifications or deletions by engineers may not have the intended effect.

        Returns:
            AuditResult: An object containing the audit results.

        """
        logging.debug("Auditing duplicate security rules...")

        def key_function(obj):
            return (
                tuple(sorted(obj.from_zone)),
                tuple(sorted(obj.to_zone)),
                tuple(sorted(obj.source_address)),
                tuple(sorted(obj.destination_address)),
                tuple(sorted(obj.destination_service)),
                (
                    tuple(sorted(obj.translated_destination))
                    if obj.translated_destination is not None
                    else None
                ),
                (
                    tuple(sorted(obj.translated_source))
                    if obj.translated_source is not None
                    else None
                ),
            )

        duplicates = self._find_duplicates(self.parsed_config.nat_rules)

        if len(duplicates):
            recommendation = (
                "Review the duplicate nat rules and remove the unnecessary rules."
            )
        else:
            recommendation = None
        return AuditResult(
            title="Duplicates total",
            category=AuditCategory.NAT,
            description="These are the nat rules that have the same source zone, destination zone, source address, destination address, destination port, translated address. Having duplicate security rules can lead to operational complications, as modifications or deletions by engineers may not have the intended effect.",
            count=len(duplicates),
            raw_output=duplicates,
            priority=AuditPriority.HIGH,
            show_raw_output=True,
            recommendation=recommendation,
        )

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

        condition = lambda rule: any(
            keyword in rule.name.lower() for keyword in keywords
        )
        matches = self._rule_search(condition)

        if len(matches) > 0:
            recommendation = "Remove the rule if they are not required."
        else:
            recommendation = None

        return AuditResult(
            title="Name contains temporary keywords",
            category=AuditCategory.NAT,
            description=f"These are the nat rules that contain names like {','.join(keywords)} implying a temporary rule. Temporary rules that have not been removed can lead to security vulnerabilities.",
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

        condition = lambda rule: any(
            keyword in rule.name.lower() for keyword in keywords
        )
        matches = self._rule_search(condition)

        if len(matches) > 0:
            recommendation = "Remove the rule if they are not required."
        else:
            recommendation = None

        return AuditResult(
            title="Name contains test keyword",
            category=AuditCategory.NAT,
            description=f"These are the nat rules that contain names like {','.join(keywords)} implying a temporary rule. Temporary rules that have not been removed can lead to security vulnerabilities.",
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

        condition = lambda rule: any(
            keyword in rule.name.lower() for keyword in keywords
        )
        matches = self._rule_search(condition)

        if len(matches) > 0:
            recommendation = "Remove the rule if they are not required."
        else:
            recommendation = None

        return AuditResult(
            title="Name contains poc keyword",
            category=AuditCategory.NAT,
            description=f"These are the nat rules that contain names like {','.join(keywords)} implying a temporary rule. Temporary rules that have not been removed can lead to security vulnerabilities.",
            count=len(matches),
            raw_output=matches,
            priority=AuditPriority.LOW,
            show_raw_output=True,
            recommendation=recommendation,
            group=AuditGroup.TEMP_KEYWORDS,
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
            recommendation = "Add a description to the rule to assist in auditing and understanding the purpose of the rule."
        else:
            recommendation = None

        return AuditResult(
            title="Description Missing",
            category=AuditCategory.NAT,
            description="These are the nat rules that do not have a description. Providing a description can help in understanding the purpose of the rule and facilitates easier auditing.",
            count=len(matches),
            raw_output=matches,
            priority=AuditPriority.MEDIUM,
            show_raw_output=True,
            recommendation=recommendation,
        )

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
            category=AuditCategory.NAT,
            description="These are the nat rules that are disabled.",
            count=len(matches),
            raw_output=matches,
            priority=AuditPriority.INFO,
            show_raw_output=True,
        )

    def audit_overlapping_rules(self, include_devices=False) -> AuditResult:
        """Audit overlapping rules.

        Returns:
            AuditResult: An object containing the audit results.
        """
        logging.debug("Auditing overlapping rules...")
        overlapping_rules = self._find_overlapping_rules(include_devices)

        if include_devices:
            title = "Overlapping rules"
            description = "These are the nat rules that are a subset of another rule. This can can lead to shadowed rules, ambiguity, and can lead to operational complications, as modifications or deletions by engineers may not have the intended effect."
        else:
            title = "Overlapping rules excluding devices"
            description = (
                "These are the nat rules that are a subset of another rule excluding devices. This can can lead to shadowed rules, ambiguity, and can lead to operational complications, as modifications or deletions by engineers may not have the intended effect."
            )

        if len(overlapping_rules) > 0:
            recommendation = "Remove the overlapping rules"
        else:
            recommendation = None

        return AuditResult(
            title=title,
            category=AuditCategory.NAT,
            description=description,
            count=len(overlapping_rules),
            raw_output=overlapping_rules,
            priority=AuditPriority.HIGH,
            show_raw_output=True,
            recommendation=recommendation,
        )

    def _find_overlapping_rules(self, include_devices=False) -> List[Tuple[str, str]]:
        """Find overlapping security rules.

        Returns:
            List[Tuple[str, str]]: A list of tuples representing the overlapping rule pairs.
        """
        overlapping_rules = []

        # Iterate through each pair of rules
        for i, rule1 in enumerate(self.parsed_config.nat_rules):
            for j, rule2 in enumerate(self.parsed_config.nat_rules):
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

    def audit_nat_exact_match_rules(self) -> AuditResult:
        """Audit exact match matching nat and security rules.

        Returns:
        AuditResult: An object containing the audit results.
        """
        logging.debug("Auditing matching nat and security rules...")

        matches = self._find_nat_rule_exact_matches(
            self.parsed_config.nat_rules, self.parsed_config.security_rules
        )
        return AuditResult(
            title="Matched security rules",
            category=AuditCategory.NAT,
            description="These are the nat rules that have an exact matching security rule ie. the same source zone, destination zone, source address, destination address.",
            count=len(matches),
            raw_output=matches,
            priority=AuditPriority.INFO,
            show_raw_output=True,
        )

    def _find_nat_rule_exact_matches(self, nat_list: List[Nat], rule_list: List[Rule]):
        matches = []
        for nat in nat_list:
            for rule in rule_list:
                # Check that all criteria match
                if (
                    set(nat.from_zone) == set(rule.from_zone)
                    and set(nat.to_zone) == set(rule.to_zone)
                    and set(nat.source_address) == set(rule.source_address)
                    and set(nat.destination_address) == set(rule.destination_address)
                ):
                    matches.append((nat, rule))
        return matches

    def audit_nat_subset_of_rules(self) -> AuditResult:
        """Audit nat subset security rules. (experimental)

        Returns:
            AuditResult: An object containing the audit results.
        """
        logging.debug("Auditing nat subset of security rules...")

        matches = self._find_nat_subset_of_rule(
            self.parsed_config.nat_rules, self.parsed_config.security_rules
        )
        return AuditResult(
            title="Subset of security rules",
            category=AuditCategory.NAT,
            description="These are the nat rules that are a subset of a security rule ie. source zone, destination zone, source address, destination address.",
            count=len(matches),
            raw_output=matches,
            priority=AuditPriority.INFO,
            show_raw_output=True,
        )

    def _find_nat_subset_of_rule(self, nat_list: List[Nat], rule_list: List[Rule]):
        matches = []
        for nat in nat_list:
            for rule in rule_list:
                # Check if each field in the Nat object is a subset of the corresponding field in the Rule object
                if (
                    set(nat.from_zone).issubset(set(rule.from_zone))
                    and set(nat.to_zone).issubset(set(rule.to_zone))
                    and set(nat.source_address).issubset(set(rule.source_address))
                    and set(nat.destination_address).issubset(
                        set(rule.destination_address)
                    )
                ):
                    matches.append((nat, rule))
        return matches

    def _find_nat_rule_subset_matches(self, nat_list: List[Nat], rule_list: List[Rule]):
        matches = []
        for nat in nat_list:
            for rule in rule_list:
                # Check if each field in the Nat object is a subset of the corresponding field in the Rule object
                if (
                    set(nat.from_zone).issubset(set(rule.from_zone))
                    and set(nat.to_zone).issubset(set(rule.to_zone))
                    and set(nat.source_address).issubset(set(rule.source_address))
                    and set(nat.destination_address).issubset(
                        set(rule.destination_address)
                    )
                ):
                    matches.append((nat, rule))
        return matches

    def audit_rules_subset_of_nat(self) -> AuditResult:
        """Audit rules that are a subset of the  nat rules. (experimental)

        Returns:
        AuditResult: An object containing the audit results.
        """
        logging.debug("Auditing rules subset of nat rules...")

        matches = self._find_nat_rule_subset_matches(
            self.parsed_config.nat_rules, self.parsed_config.security_rules
        )
        return AuditResult(
            title="rules subset of nat",
            category=AuditCategory.NAT,
            description="These are the nat rules that are a subset of a security rule ie. the source zone, destination zone, source address, destination address.",
            count=len(matches),
            raw_output=matches,
            priority=AuditPriority.INFO,
            show_raw_output=True,
        )

    def _find_nat_rule_subset_matches(self, nat_list: List[Nat], rule_list: List[Rule]):
        matches = []
        for nat in nat_list:
            for rule in rule_list:
                # Check if each field in the Nat object is a subset of the corresponding field in the Rule object
                if (
                    set(rule.from_zone).issubset(set(nat.from_zone))
                    and set(rule.to_zone).issubset(set(nat.to_zone))
                    and set(rule.source_address).issubset(set(nat.source_address))
                    and set(rule.destination_address).issubset(
                        set(nat.destination_address)
                    )
                ):
                    matches.append((nat, rule))
        return matches
