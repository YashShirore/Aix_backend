import pytest

from firewall_analyzer.models.firewall_models import (
    Rule,
    Nat,
)
nat1 = Nat(
    name="Nat1",
    uuid="uuid1",
    from_zone=["zone1"],
    to_zone=["zone2"],
    source_address=["source1"],
    destination_address=["dest1"],
    translated_destination="trans_dest1",
    translated_source="trans_source1",
    destination_service=["port1"],
    description="First nat",
    rule_number=1,
    scope="global",
    disabled=False,
)
nat2 = Nat(
    name="Nat2",
    uuid="uuid2",
    from_zone=["zone3"],
    to_zone=["zone4"],
    source_address=["source2"],
    destination_address=["dest2"],
    translated_destination="trans_dest2",
    translated_source="trans_source2",
    destination_service=["port2"],
    description="Second nat",
    rule_number=2,
    scope="global",
    disabled=False,
)
nat3 = Nat(
    name="Nat3",
    uuid="uuid1",
    from_zone=["zone1"],
    to_zone=["zone2"],
    source_address=["source1"],
    destination_address=["dest1"],
    translated_destination="trans_dest1",
    translated_source="trans_source1",
    destination_service=["port1"],
    description="First nat",
    rule_number=3,
    scope="global",
    disabled=False,
)

nats = [nat1, nat2, nat3]


def test_nat_is_eq():
    assert nat1 == nat3


def test_nat_not_eq():
    assert nat1 != nat2


def test_test_rule_hash():
    unique_nats = set(nats)
    assert len(unique_nats) == 2
