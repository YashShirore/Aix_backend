# Models for firewall configuration objects

import re
from typing import Any, Dict, List, Optional, Set

from netaddr import IPNetwork, IPRange
from pydantic import BaseModel, field_validator, model_validator


class Device(BaseModel):
    """Class representing a device."""

    hostname: Optional[str] = None
    id: Optional[str] = None
    ip_address: Optional[str] = None
    netmask: Optional[str] = None
    model: Optional[str] = None
    serial_number: Optional[str] = None
    default_gateway: Optional[str] = None
    domain: Optional[str] = None
    ssl_tls_service_profile: Optional[str] = None
    update_server: Optional[str] = None
    secure_proxy_server: Optional[str] = None
    secure_proxy_port: Optional[int] = None
    vsys_display_name: Optional[dict] = None
    vsys_ids: Optional[set] = None
    snmp_community: Optional[str] = None
    software_version: Optional[str] = None


    def __eq__(self, other: Any) -> bool:
        """
        Check if two AddressObject instances are equal. Only compare the range, netmask, and fqdn fields.
        Args:
            other (Any): The other object to compare.
        Returns:
            bool: True if the objects are equal, False otherwise.
        """
        if not isinstance(other, AddressObject):
            return NotImplemented
        return (
            self.id == other.id
            and self.hostname == other.hostname
        )

    def __hash__(self) -> int:
        """
        Generate a hash value for the AddressObject instance. Only include the range, netmask, and fqdn fields.
        Returns:
            int: The hash value.
        """
        return hash((self.id, self.hostname))


class AddressObject(BaseModel):
    """Class representing an address object."""

    name: str
    range: Optional[str] = None
    netmask: Optional[str] = None
    fqdn: Optional[str] = None
    scope: Optional[str] = None
    tags: List[str] = []
    description: Optional[str] = None
    nat: Optional[str] = None

    def get_number_of_hosts(self) -> int:
        """
        Calculates the total number of hosts based on the provided network information.

        Returns:
            int: The total number of hosts.

        Raises:
            None
        """
        total: int = 0
        if self.netmask:
            ip_network: IPNetwork = IPNetwork(self.netmask)
            total += ip_network.size
        elif self.range:
            ip_range: IPRange = IPRange(
                self.range.split("-")[0], self.range.split("-")[1]
            )
            total += ip_range.size
        elif self.fqdn:
            total += 1
        return total

    @model_validator(mode="after")
    def check_one_of(cls, values):
        """
        Validates that only one of range, netmask, or fqdn is provided at a time.

        Args:
            values (AddressObject): The address object to validate.

        Returns:
            AddressObject: The validated address object.

        Raises:
            ValueError: If more than one value is set or if none of the values are provided.
        """
        range_val: Optional[str] = values.range
        netmask_val: Optional[str] = values.netmask
        fqdn_val: Optional[str] = values.fqdn

        # Check if more than one value is set
        provided_fields: List[bool] = [
            bool(range_val),
            bool(netmask_val),
            bool(fqdn_val),
        ]
        if sum(provided_fields) > 1:
            raise ValueError(
                "Only one of range, netmask, or fqdn can be provided at a time."
            )

        # Ensure at least one is provided
        #if not any(provided_fields):
            #raise ValueError("One of range, netmask, or fqdn must be provided.")

        return values

    @field_validator("range")
    def validate_range(cls, value: Optional[str]) -> Optional[str]:
        """
        Validates the range field of the address object.

        Args:
            value (Optional[str]): The range value to validate.

        Returns:
            Optional[str]: The validated range value.

        Raises:
            ValueError: If the range is not in the format 'ip_address - ip_address' or if the IP addresses are invalid.
        """
        if value is None:
            return value

        ip_range_pattern = re.compile(
            r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*-\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$"
        )
        match = ip_range_pattern.match(value)
        if not match:
            raise ValueError("Range must be in the format 'ip_address - ip_address'")

        start_ip, end_ip = match.groups()
        for ip in [start_ip, end_ip]:
            parts = ip.split(".")
            if len(parts) != 4 or not all(0 <= int(part) < 256 for part in parts):
                raise ValueError(f"Invalid IP address: {ip}")
        return value

    def __eq__(self, other: Any) -> bool:
        """
        Check if two AddressObject instances are equal. Only compare the range, netmask, and fqdn fields.
        Args:
            other (Any): The other object to compare.
        Returns:
            bool: True if the objects are equal, False otherwise.
        """
        if not isinstance(other, AddressObject):
            return NotImplemented
        return (
            self.range == other.range
            and self.netmask == other.netmask
            and self.fqdn == other.fqdn
        )

    def __hash__(self) -> int:
        """
        Generate a hash value for the AddressObject instance. Only include the range, netmask, and fqdn fields.
        Returns:
            int: The hash value.
        """
        return hash((self.range, self.netmask, self.fqdn))


class AddressGroup(BaseModel):
    """Class representing an address group."""

    name: str
    id: Optional[str] = None
    members: List[str] = []
    scope: Optional[str] = None
    tags: List[str] = []
    description: Optional[str] = None

    def __eq__(self, other: Any) -> bool:
        """
        Check if two AddressGroup instances are equal. Only compare the members field.

        Args:
            other (Any): The other object to compare.

        Returns:
            bool: True if the objects are equal, False otherwise.
        """
        if not isinstance(other, AddressGroup):
            return NotImplemented
        return self.members == other.members

    def __hash__(self) -> int:
        """
        Generate a hash value for the AddressGroup instance. Only include the members field.

        Returns:
            int: The hash value.
        """
        return hash((tuple(self.members)))


class ServiceObject(BaseModel):
    """Class representing an service object."""

    name: str
    protocol: str
    port: str
    scope: Optional[str] = None
    tags: List[str] = []
    description: Optional[str] = None
    src_or_dst: Optional[str] = None

    @field_validator("src_or_dst")
    def validate_src_or_dst(cls, v: Optional[str]) -> Optional[str]:
        """
        Validates the src_or_dst field of the service object.

        Args:
            v (Optional[str]): The src_or_dst value to validate.

        Returns:
            Optional[str]: The validated src_or_dst value.

        Raises:
            ValueError: If the src_or_dst value is not one of {None, 'source', 'destination'}.
        """
        allowed_values: Set[Optional[str]] = {None, "source", "destination"}
        if v not in allowed_values:
            raise ValueError(f"src_or_dst must be one of {allowed_values}")
        return v

    def __eq__(self, other: Any) -> bool:
        """
        Check if two ServiceObject instances are equal. Only compare the protocol, port, and src_or_dst fields.

        Args:
            other (Any): The other object to compare.

        Returns:
            bool: True if the objects are equal, False otherwise.
        """
        if not isinstance(other, ServiceObject):
            return NotImplemented
        return (
            self.protocol == other.protocol
            and self.port == other.port
            and self.src_or_dst == other.src_or_dst
        )

    def __hash__(self) -> int:
        """
        Generate a hash value for the ServiceObject instance. Only include the protocol, port, and src_or_dst fields.

        Returns:
            int: The hash value.
        """
        return hash((self.protocol, self.port, self.src_or_dst))


class ServiceGroup(BaseModel):
    """Class representing a service group."""

    name: str
    members: List[str] = []
    scope: Optional[str] = None
    tags: List[str] = []
    description: Optional[str] = None

    def __eq__(self, other: Any) -> bool:
        """
        Check if two ServiceGroup instances are equal. Only compare the members field.

        Args:
            other (Any): The other object to compare.

        Returns:
            bool: True if the objects are equal, False otherwise.
        """
        if not isinstance(other, ServiceGroup):
            return NotImplemented
        return self.members == other.members

    def __hash__(self) -> int:
        """
        Generate a hash value for the ServiceGroup instance. Only include the members field.

        Returns:
            int: The hash value.
        """
        return hash((tuple(self.members)))


class Schedule(BaseModel):
    """Class representing a schedule."""

    name: str
    description: Optional[str] = None
    members: List[str] = []


class Rule(BaseModel):
    """Class representing a security rule."""

    name: str
    uuid: str
    from_zone: List[str] = []
    to_zone: List[str] = []
    source_address: List[str] = []
    destination_address: List[str] = []
    destination_service: Optional[List[str]] = []
    source_service: Optional[List[str]] = []
    action: str
    description: Optional[str] = None
    log_setting: Optional[str] = None
    applications: List[str] = []
    tags: List[str] = []
    rule_number: Optional[int] = None
    scope: Optional[str] = None
    disabled: bool = False
    schedule: Optional[str] = None
    devices: Optional[List[tuple]] = None

    @field_validator("action")
    def check_action(cls, value: str) -> str:
        """
        Validate the action field of the rule.

        Args:
            value (str): The action value to validate.

        Returns:
            str: The validated action value.

        Raises:
            ValueError: If the action value is not one of {"allow", "deny", "reject", "drop"}.
        """
        if value not in {"allow", "deny", "reject", "drop"}:
            raise ValueError("Invalid action")
        return value

    def __eq__(self, other: Any) -> bool:
        """
        Check if two Rule instances are equal. Only compare the relevant fields.

        Args:
            other (Any): The other object to compare.

        Returns:
            bool: True if the objects are equal, False otherwise.
        """
        if not isinstance(other, Rule):
            return NotImplemented
        return (
            self.from_zone == other.from_zone
            and self.to_zone == other.to_zone
            and self.source_address == other.source_address
            and self.destination_address == other.destination_address
            and self.destination_service == other.destination_service
            and self.source_service == other.source_service
            and self.action == other.action
            and self.applications == other.applications
        )

    def __hash__(self) -> int:
        """
        Generate a hash value for the Rule instance. Only include the relevant fields.

        Returns:
            int: The hash value.
        """
        return hash(
            (
                tuple(self.from_zone),
                tuple(self.to_zone),
                tuple(self.source_address),
                tuple(self.destination_address),
                tuple(self.destination_service),
                tuple(self.source_service),
                self.action,
                tuple(self.applications),
            )
        )


class Nat(BaseModel):
    """Class representing a NAT object."""

    name: str
    uuid: str
    from_zone: List[str]
    to_zone: List[str]
    source_address: List[str]
    destination_address: List[str]
    translated_destination: Optional[str] = None
    translated_source: Optional[str] = None
    destination_service: Any = None
    description: Optional[str] = None
    rule_number: Optional[int] = None
    scope: Optional[str] = None
    disabled: bool = False
    devices: Optional[List[tuple]] = None

    def __eq__(self, other: Any) -> bool:
        """
        Check if two Nat instances are equal. Only compare the relevant fields.

        Args:
            other (Any): The other object to compare.

        Returns:
            bool: True if the objects are equal, False otherwise.
        """
        if not isinstance(other, Nat):
            return NotImplemented
        return (
            self.from_zone == other.from_zone
            and self.to_zone == other.to_zone
            and self.source_address == other.source_address
            and self.destination_address == other.destination_address
            and self.translated_destination == other.translated_destination
            and self.translated_source == other.translated_source
            and self.destination_service == other.destination_service
        )

    def __hash__(self) -> int:
        """
        Generate a hash value for the Nat instance. Only include the relevant fields.

        Returns:
            int: The hash value.
        """
        return hash(
            (
                self.uuid,
                tuple(self.from_zone),
                tuple(self.to_zone),
                tuple(self.source_address),
                tuple(self.destination_address),
                self.translated_destination,
                self.translated_source,
                tuple(self.destination_service),
            )
        )


    
class FirewallConfiguration(BaseModel):
    """Class representing the entire firewall configuration."""

    address_objects: List[AddressObject] = []
    address_groups: List[AddressGroup] = []
    service_objects: List[ServiceObject] = []
    service_groups: List[ServiceGroup] = []
    security_rules: List[Rule] = []
    system_info: Dict[str, Dict[str, List[str]]] = {}
    schedules: List[Schedule] = []
    nat_rules: List[Nat] = []
    devices: List[Device] = []
    templates: List[Dict[str, Any]] = []
