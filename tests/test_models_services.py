import pytest

from firewall_analyzer.models.firewall_models import (
    ServiceGroup,
    ServiceObject,
)


service_object1 = ServiceObject(
    name="Service1",
    protocol="tcp",
    port="80",
    scope="global",
    tags=["tag1"],
    description="First service object",
)
service_object2 = ServiceObject(
    name="Service2",
    protocol="udp",
    port="53",
    scope="global",
    tags=["tag2"],
    description="Second service object",
)
service_object3 = ServiceObject(
    name="Service3",
    protocol="tcp",
    port="80",
    scope="global",
    tags=["tag1"],
    description="Third service object",
)

service_objects = [service_object1, service_object2, service_object3]


def test_parse_service_object_is_eq():
    assert service_object1 == service_object3


def test_parse_service_object_not_eq():
    assert service_object1 != service_object2


def test_parse_service_object_hash():
    unique_service_object = set(service_objects)
    assert len(unique_service_object) == 2


service_group1 = ServiceGroup(
    name="Group1",
    members=["Service1", "Service2"],
    scope="global",
    tags=["tag1"],
    description="First service group",
)
service_group2 = ServiceGroup(
    name="Group2",
    members=["Service3", "Service4"],
    scope="global",
    tags=["tag2"],
    description="Second service group",
)
service_group3 = ServiceGroup(
    name="Group1",
    members=["Service1", "Service2"],
    scope="global",
    tags=["tag1"],
    description="First service group",
)

service_groups = [service_group1, service_group2, service_group3]


def test_parse_service_group_is_eq():
    assert service_group1 == service_group3


def test_parse_service_group_not_eq():
    assert service_group1 != service_group2


def test_parse_service_group_hash():
    unique_service_groups = set(service_groups)
    assert len(unique_service_groups) == 2
