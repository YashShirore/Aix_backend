import pytest

from firewall_analyzer.models.firewall_models import (
    Rule,
)


rule1 = Rule(
    name="Rule1",
    uuid="uuid1",
    from_zone=["zone1"],
    to_zone=["zone2"],
    source_address=["source1"],
    destination_address=["dest1"],
    destination_service=["port1"],
    action="allow",
    description="First rule",
    log_setting="log1",
    applications=["app1"],
    tags=["tag1"],
    rule_number=1,
    scope="global",
    disabled=False,
    schedule="schedule1",
    #devices={"device1": "device1"}
)
rule2 = Rule(
    name="Rule2",
    uuid="uuid2",
    from_zone=["zone3"],
    to_zone=["zone4"],
    source_address=["source2"],
    destination_address=["dest2"],
    destination_service=["port2"],
    action="deny",
    description="Second rule",
    log_setting="log2",
    applications=["app2"],
    tags=["tag2"],
    rule_number=2,
    scope="global",
    disabled=False,
    schedule="schedule2",
    #devices={"device2": "device2"}
)
rule3 = Rule(
    name="Rule3",
    uuid="uuid3",
    from_zone=["zone1"],
    to_zone=["zone2"],
    source_address=["source1"],
    destination_address=["dest1"],
    destination_service=["port1"],
    action="allow",
    description="First rule",
    log_setting="log1",
    applications=["app1"],
    tags=["tag1"],
    rule_number=1,
    scope="global",
    disabled=False,
    schedule="schedule1",
    #devices={"device3": "device3"}
)
rules = [rule1, rule2, rule3]


def test_rule_is_eq():
    assert rule1 == rule3


def test_rule_not_eq():
    assert rule1 != rule2


def test_test_rule_hash():
    unique_rules = set(rules)
    assert len(unique_rules) == 2


#def test_rule_is_subset_of():
#    rule1 = Rule(
#        name="Rule1",
#        uuid="uuid1",
#        from_zone=["zone1"],
#        to_zone=["zone2"],
#        source_address=["source1"],
#        destination_address=["dest1"],
#        destination_service=["port1"],
#        action="allow",
#        description="First rule",
#        log_setting="log1",
#        applications=["app1"],
#        tags=["tag1"],
#        rule_number=1,
#        scope="global",
#        disabled=False,
#        schedule="schedule1",
#        devices={"device3": "device3"}
#    )
#
#    rule2 = Rule(
#        name="Rule2",
#        uuid="uuid2",
#        from_zone=["zone1"],
#        to_zone=["zone2"],
#        source_address=["source1"],
#        destination_address=["dest1", "dest2"],
#        destination_service=["port1"],
#        action="allow",
#        description="First rule",
#        log_setting="log1",
#        applications=["app1"],
#        tags=["tag2"],
#        rule_number=1,
#        scope="global",
#        disabled=False,
#        schedule="schedule1",
#        devices={"device3": "device3"}
#    )
#
#    assert rule1.is_subset_of(rule2)
#    assert not rule2.is_subset_of(rule1)
#
#ruleA = Rule(
#    name='Oracle_OEM_Agent_04',
#    uuid='0134c332-d5d9-4c19-b95e-4bcce411f268',
#    from_zone=['VSYS-EXTERNAL'],
#    to_zone=['Oracle_VPN'],
#    source_address=['10.165.72.204', '10.165.72.206', '10.165.72.208'],
#    destination_address=['192.168.100.2', '10.188.44.141', '10.189.44.141'],
#    destination_service=['TCP_1159'],
#    action='allow',
#    description='modified by CHG002109482',
#    log_setting='NC11PANPAN01_NC12PANPAN01',
#    applications=['any'],
#    tags=[],
#    rule_number=53,
#    scope='pre-rulebase',
#    disabled=False,
#    schedule=None,
#    devices={'015701001280': ['vsys1'], '015701001298': ['vsys1'], '015701001300': ['vsys1'], '015701001306': ['vsys1']}
#)
#
#
#ruleB = Rule(
#    name='CHG002083963-2-1',
#    uuid='7b94c5f4-418b-4a76-94fc-f8ba409b2cb5',
#    from_zone=['VSYS-EXTERNAL'],
#    to_zone=['Oracle_VPN'],
#    source_address=['10.165.72.204', '10.165.72.206', '10.165.72.208'],
#    destination_address=['192.168.100.2', '10.189.44.141', '10.188.44.141'],
#    destination_service=['TCP_1159'],
#    action='allow',
#    description='modified by CHG002109482',
#    log_setting='NC11PANPAN01_NC12PANPAN01',
#    applications=['any'],
#    tags=[],
#    rule_number=53,
#    scope='pre-rulebase',
#    disabled=False,
#    schedule=None,
#    devices={'015701001280': ['vsys1'], '015701001298': ['vsys1'], '015701001300': ['vsys1'], '015701001306': ['vsys1']}
#)
#
#
#def test_rule_is_subset_of_mod():
#
#    assert ruleA.is_subset_of(ruleB)
#