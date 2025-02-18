import pytest

from firewall_analyzer.models.firewall_models import (
    AddressGroup,
    AddressObject,
)

address_object1 = AddressObject(
    name="Object1",
    netmask="10.165.71.0/26",
    scope="global",
    tags=["tag1"],
    description="First address object",
)
address_object2 = AddressObject(
    name="Object2",
    fqdn="a.example.com",
    scope="global",
    tags=["tag2"],
    description="Second address object",
)
address_object3 = AddressObject(
    name="Object3",
    netmask="10.165.71.0/26",
    scope="global",
    tags=["tag1"],
    description="Third address object",
)

address_objects = [address_object1, address_object2, address_object3]


def test_parse_address_is_eq():
    assert address_object1 == address_object3


def test_parse_address_not_eq():
    assert address_object1 != address_object2


def test_parse_address_hash():
    unique_address_objects = set(address_objects)
    assert len(unique_address_objects) == 2


address_group1 = AddressGroup(
    name="Group1",
    id="1",
    members=["Member1", "Member2"],
    scope="global",
    tags=["tag1"],
    description="First address group",
)
address_group2 = AddressGroup(
    name="Group2",
    id="2",
    members=["Member3", "Member4"],
    scope="global",
    tags=["tag2"],
    description="Second address group",
)
address_group3 = AddressGroup(
    name="Group3",
    id="3",
    members=["Member1", "Member2"],
    scope="global",
    tags=["tag1"],
    description="Third address group",
)
address_groups = [address_group1, address_group2, address_group3]


def test_parse_address_group_is_eq():
    assert address_group1 == address_group3


def test_parse_address_group_not_eq():
    assert address_group1 != address_group2


def test_parse_address_group_hash():
    unique_address_groups = set(address_groups)
    assert len(unique_address_groups) == 2
