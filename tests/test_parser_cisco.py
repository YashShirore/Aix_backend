from firewall_analyzer.parser.cisco.cisco_asa_parser import CiscoASAParser
import pytest
from firewall_analyzer.models.firewall_models import (
    AddressObject,
    AddressGroup,
    ServiceObject,
    ServiceGroup,
    Rule,
)

SAMPLE_ASA_FILE = "./tests/data/asa.txt"

@pytest.fixture
def parser(input_files=[SAMPLE_ASA_FILE]):
    parser = CiscoASAParser(input_files)
    return parser


def test_init(parser):
    assert parser


def test_parse_all(parser):
    parsed_config = parser.parse_all()

    assert parsed_config.devices[0].hostname == "myhostname1"
    assert parsed_config.address_objects == [
        AddressObject(
            name="obj_single_host",
            range=None,
            netmask="192.168.1.100",
            fqdn=None,
            scope=None,
            tags=[],
            description=None,
            nat=None,
        ),
        AddressObject(
            name="obj_network",
            range=None,
            netmask="192.168.1.0/24",
            fqdn=None,
            scope=None,
            tags=[],
            description=None,
            nat=None,
        ),
        AddressObject(
            name="obj_natted_host",
            range=None,
            netmask="192.168.1.100",
            fqdn=None,
            scope=None,
            tags=[],
            description=None,
        ),
        AddressObject(
            name="obj_natted_network",
            range=None,
            netmask="192.168.1.0/24",
            fqdn=None,
            scope=None,
            tags=[],
            description=None,
        ),
        AddressObject(
            name="obj_ip_range",
            range="192.168.1.100-192.168.1.150",
            netmask=None,
            fqdn=None,
            scope=None,
            tags=[],
            description=None,
            nat=None,
        ),
        AddressObject(
            name="obj_fqdn",
            range=None,
            netmask=None,
            fqdn="www.example.com",
            scope=None,
            tags=[],
            description=None,
            nat=None,
        ),
    ]
    
    assert parsed_config.address_groups == [
        AddressGroup(
            name="obj_group",
            id=None,
            members=["obj_host1", "obj_host2", "obj_network1"],
            scope=None,
            tags=[],
            description=None,
        )
    ]

    assert parsed_config.service_objects == [
        ServiceObject(
            name="NTP",
            protocol="udp",
            port="123",
            scope=None,
            tags=[],
            description=None,
            src_or_dst="source",
        ),
        ServiceObject(
            name="HTTP",
            protocol="tcp",
            port="80",
            scope=None,
            tags=[],
            description=None,
            src_or_dst="destination",
        ),
        ServiceObject(
            name="HTTPS",
            protocol="tcp",
            port="443",
            scope=None,
            tags=[],
            description=None,
            src_or_dst="destination",
        ),
    ]

    assert parsed_config.service_groups == [
        ServiceGroup(
            name="WEB_SERVICES",
            members=["HTTP", "HTTPS"],
            scope=None,
            tags=[],
            description="Web Services Group",
        )
    ]
     
def test_software_versions(parser):
    parsed_cofig = parser.parse_all()

    assert parsed_cofig.devices[0].software_version == "9.7(1)"

# assert parser.parsed_config.security_rules == []
