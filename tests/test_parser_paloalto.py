import pytest
from lxml import etree
from firewall_analyzer.parser.paloalto.paloalto_panos_parser import PaloAltoPANOSParser
from firewall_analyzer.models.firewall_models import (
    FirewallConfiguration,
    Rule,
    AddressObject,
    AddressGroup,
    ServiceObject,
    ServiceGroup,
)

SAMPLE_CONFIG_FILE = "./tests/data/paloalto.xml"


@pytest.fixture
def parser(input_files=[SAMPLE_CONFIG_FILE]):
    parser = PaloAltoPANOSParser(input_files)
    return parser


def test_init(parser):
    assert parser


def test_parse_all(parser):
    config = parser.parse_all()
    assert config.security_rules == [
        Rule(
            name="rule1",
            uuid="012bc273-1",
            from_zone=["VSYS-EXTERNAL"],
            to_zone=["CorpWAN-Ext"],
            source_address=[
                "10.231.202.80",
                "10.231.202.83",
                "10.231.218.80",
                "10.231.218.83",
            ],
            destination_address=[
                "10.231.135.186",
                "10.231.135.187",
                "10.231.172.92",
                "10.231.172.93",
                "10.231.172.95",
            ],
            destination_service=["TCP-1414"],
            source_service=[],
            action="allow",
            description="mydescription",
            log_setting="log_settings",
            applications=["any"],
            tags=[],
            rule_number=1,
            scope="post-rulebase",
            disabled=False,
            schedule=None,
        ),
        Rule(
            name="rule2",
            uuid="ab6fee1a-2",
            from_zone=["CorpWAN-Ext"],
            to_zone=["VSYS-EXTERNAL"],
            source_address=[
                "10.231.202.80",
                "10.231.202.83",
                "10.231.218.80",
                "10.231.218.83",
            ],
            destination_address=[
                "10.231.135.186",
                "10.231.135.187",
                "10.231.172.92",
                "10.231.172.93",
                "10.231.172.95",
            ],
            destination_service=["TCP-1414"],
            source_service=[],
            action="allow",
            description="mydescription",
            log_setting="log_settings",
            applications=["any"],
            tags=[],
            rule_number=2,
            scope="post-rulebase",
            disabled=False,
            schedule=None,
        ),
        Rule(
            name="rule3",
            uuid="ab6fee1a-3",
            from_zone=["CorpWAN-Ext"],
            to_zone=["VSYS-EXTERNAL"],
            source_address=[
                "10.231.202.80",
                "10.231.202.83",
                "10.231.218.80",
                "10.231.218.83",
            ],
            destination_address=[
                "10.231.135.186",
                "10.231.135.187",
                "10.231.172.92",
                "10.231.172.93",
                "10.231.172.95",
            ],
            destination_service=["TCP-1414"],
            source_service=[],
            action="allow",
            description="my_description",
            log_setting="log_settings",
            applications=["any"],
            tags=[],
            rule_number=3,
            scope="post-rulebase",
            disabled=False,
            schedule=None,
        ),
    ]
