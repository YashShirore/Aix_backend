import logging
import re
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd
from lxml import etree

from firewall_analyzer.models.firewall_models import (
    AddressGroup,
    AddressObject,
    FirewallConfiguration,
    Nat,
    Rule,
    Schedule,
    ServiceGroup,
    ServiceObject,
    Device,
)

from ..base import BaseParser


class PaloAltoPANOSParser(BaseParser):
    """
    Class for parsing XML firewall configuration files.

    Attributes:
        input_files: List of XML file paths to parse.
        file_contents: List of file contents.
        object_scopes: List of object scopes specific to the platform.
    """

    object_scopes = ["shared", "device-group"]
    rule_scopes = ["pre-rulebase", "post-rulebase"]

    def parse_all(self) -> FirewallConfiguration:
        """Parse all necessary information from XML."""
        self.file_contents = self._read_files(self.input_files)
        for fname, contents in self.file_contents.items():
            self._parse_device_info(fname, contents)
            self._parse_address_objects(contents)
            self._parse_address_groups(contents)
            self._parse_service_objects(contents)
            self._parse_service_groups(contents)
            self._parse_security_rules(contents)
            self._parse_schedules(contents)
            self._parse_nat_rules(contents)
        #import ipdb;ipdb.set_trace()
        return self.parsed_config

    def _read_file(self, input_file: str) -> etree.Element:
        """Read and parse the XML file.

        Args:
            input_file (str): Path to the input XML file.

        Returns:
            etree.Element: The root element of the parsed XML.
        """
        try:
            with open(input_file, "rb") as file:
                tree = etree.parse(file)
                root = tree.getroot()
                logging.debug("Successfully parsed XML file.")
            return root
        except Exception as e:
            logging.error(f"Error reading or parsing XML file: {e}")
            raise

    def _read_files(self, input_files: List[str]) -> List[etree.Element]:
        """Read and parse the XML files.

        Args:
            input_files (List[str]): List of paths to the input XML files.

        Returns:
            List[etree.Element]: List of root elements of the parsed XML.
        """
        roots = {}
        for input_file in input_files:
            roots[input_file] = self._read_file(input_file)
        return roots

    def _parse_device_info(self, input_file: str, root: etree.Element) -> None:
        """Parse the system information from the XML.

        Args:
            input_file (str): The input file name.
            root (etree.Element): The root element of the XML.
        """

        device = None
        match = re.search(r"_(.*?)\.xml", input_file)
        if match:
            device_id = match.group(1)
            logging.debug(f"Device ID: {device_id}")
            if device_id is None:
                logging.error(
                    f"Could not determine device id from file name: {input_file}"
                )
                return
            for devices in self.parsed_config.devices:
                if devices.id == device_id:
                    device = devices
                    break
        else:
            logging.error(f"Could not determine device id from file name: {input_file}")
            return
        
        if device is None:
            device = Device(id=device_id)
            self.parsed_config.devices.append(device)

        device_entries = root.xpath('.//devices/entry[@name="localhost.localdomain"]')
        hostname = None
        for entry in device_entries:
            if entry.find(".//deviceconfig/system/hostname") is not None:
                hostname = entry.find(".//deviceconfig/system/hostname").text
                device.hostname = hostname
            if entry.find(".//deviceconfig/system/ip-address") is not None:
                device.ip_address = entry.find(
                    ".//deviceconfig/system/ip-address"
                ).text
            if entry.find(".//deviceconfig/system/netmask") is not None:
                device.netmask = entry.find(
                    ".//deviceconfig/system/netmask"
                ).text
            if entry.find(".//deviceconfig/system/default-gateway") is not None:
                device.default_gateway = entry.find(
                    ".//deviceconfig/system/default-gateway"
                ).text
            if entry.find(".//deviceconfig/system/domain") is not None:
                device.domain = entry.find(".//deviceconfig/system/domain").text
            if entry.find(".//deviceconfig/system/ssl-tls-service-profile") is not None:
                device.ssl_tls_service_profile = entry.find(
                    ".//deviceconfig/system/ssl-tls-service-profile"
                ).text
            if entry.find(".//deviceconfig/system/update-server") is not None:
                device.update_server = entry.find(
                    ".//deviceconfig/system/update-server"
                ).text
            if entry.find(".//deviceconfig/system/secure-proxy-server") is not None:
                device.secure_proxy_server = entry.find(
                    ".//deviceconfig/system/secure-proxy-server"
                ).text
            if entry.find(".//deviceconfig/system/secure-proxy-port") is not None:
                device.secure_proxy_port = entry.find(
                    ".//deviceconfig/system/secure-proxy-port"
                ).text
        vsys_entries = root.xpath(
            './/devices/entry/vsys/entry[starts-with(@name, "vsys")]'
        )
        device.vsys_display_name = {}
        for entry in vsys_entries:
            if entry.find(".//display-name") is not None:
                device.vsys_display_name[entry.get("name")] = entry.find(
                    ".//display-name"
                ).text


    def _parse_address_objects(self, root: etree.Element) -> None:
        """Parse the address objects from the XML."""
        for scope in self.object_scopes:
            address_objects = root.findall(f".//{scope}//address/entry")
            for entry in address_objects:
                name = entry.get("name")
                tags = [tag.text for tag in entry.findall(".//tag/member")]
                description = (
                    entry.find(".//description").text
                    if entry.find(".//description") is not None
                    else None
                )
                for ip_range in entry.findall("ip-range"):
                    self.parsed_config.address_objects.append(
                        AddressObject(
                            name=name,
                            range=ip_range.text,
                            scope=scope,
                            tags=tags,
                            description=description,
                        )
                    )
                    break
                for ip_netmask in entry.findall("ip-netmask"):
                    self.parsed_config.address_objects.append(
                        AddressObject(
                            name=name,
                            netmask=ip_netmask.text,
                            scope=scope,
                            tags=tags,
                            description=description,
                        )
                    )
                    break
                for fqdn in entry.findall("fqdn"):
                    self.parsed_config.address_objects.append(
                        AddressObject(
                            name=name,
                            fqdn=fqdn.text,
                            scope=scope,
                            tags=tags,
                            description=description,
                        )
                    )
                    break

    def _parse_address_groups(self, root: etree.Element) -> None:
        """Parse the address group objects from the XML."""
        for scope in self.object_scopes:
            address_groups = root.findall(f".//{scope}//address-group/entry")
            for entry in address_groups:
                name: str = entry.get("name")
                id: Optional[str] = entry.find("id")
                if id is not None:
                    # check if the name already exists in the list
                    if any(
                        group.name == name
                        for group in self.parsed_config.address_groups
                    ):
                        # update the existing group
                        for group in self.parsed_config.address_groups:
                            if group.name == name:
                                group.id = id.text
                    else:
                        self.parsed_config.address_groups.append(
                            AddressGroup(name=name, id=id.text, scope=scope)
                        )
                    continue
                members = [member.text for member in entry.findall(".//member")]
                tags: List[str] = [tag.text for tag in entry.findall(".//tag/member")]
                description: Optional[str] = (
                    entry.find(".//description").text
                    if entry.find(".//description") is not None
                    else None
                )
                # check if the name is already in the list
                if any(
                    group.name == name for group in self.parsed_config.address_groups
                ):
                    # update the existing group
                    for group in self.parsed_config.address_groups:
                        if group.name == name:
                            group.members = members
                            group.tags = tags
                            group.description = description
                            group.scope = scope
                else:
                    self.parsed_config.address_groups.append(
                        AddressGroup(
                            name=name,
                            members=members,
                            scope=scope,
                            tags=tags,
                            description=description,
                        )
                    )

    def _parse_service_objects(self, root) -> None:
        """Parse the service objects from the XML."""
        for scope in self.object_scopes:
            service_objects = root.findall(f".//{scope}//service/entry")
            for entry in service_objects:
                name = entry.get("name")
                port = None
                tags = [tag.text for tag in entry.findall(".//tag/member")]
                description = (
                    entry.find(".//description").text
                    if entry.find(".//description") is not None
                    else None
                )

                for protocol in ["tcp", "udp", "icmp"]:
                    proto_elem = entry.find(f".//{protocol}")
                    if proto_elem is not None:
                        port = proto_elem.find("port")
                        if port is not None:
                            self.parsed_config.service_objects.append(
                                ServiceObject(
                                    name=name,
                                    protocol=protocol,
                                    port=port.text,
                                    scope=scope,
                                    tags=tags,
                                    description=description,
                                )
                            )
                            break

    def _parse_service_groups(self, root) -> None:
        """Parse the service group objects from the XML."""
        for scope in self.object_scopes:
            service_groups = root.findall(f".//{scope}//service-group/entry")
            for entry in service_groups:
                name = entry.get("name")
                members = [member.text for member in entry.findall(".//member")]
                tags = [tag.text for tag in entry.findall(".//tag/member")]
                description = (
                    entry.find(".//description").text
                    if entry.find(".//description") is not None
                    else None
                )
                if members:
                    self.parsed_config.service_groups.append(
                        ServiceGroup(
                            name=name,
                            members=members,
                            scope=scope,
                            tags=tags,
                            description=description,
                        )
                    )

    def _parse_security_rules(self, root) -> None:
        """Parse the security rules from the XML."""

        for scope in self.rule_scopes:
            rules = root.findall(f".//{scope}/security/rules/entry")
            rule_number_start = (len(self.parsed_config.security_rules)) + 1

            for i, entry in enumerate(rules):
                action = (
                    entry.find(".//action").text
                    if entry.find(".//action") is not None
                    else None
                )
                description = (
                    entry.find(".//description").text
                    if entry.find(".//description") is not None
                    else None
                )
                log_setting = (
                    entry.find(".//log-setting").text
                    if entry.find(".//log-setting") is not None
                    else None
                )
                disabled_setting = (
                    True
                    if (
                        entry.find(".//disabled") is not None
                        and entry.find(".//disabled").text == "yes"
                    )
                    else False
                )
                schedule = (
                    entry.find(".//schedule").text
                    if entry.find(".//schedule") is not None
                    else None
                )

                devices_settings = entry.findall(".//devices/entry")
                #import ipdb;ipdb.set_trace()
                target_device_vsys = self._get_device_targets(devices_settings)

                rule = Rule(
                    name=entry.get("name"),
                    uuid=entry.get("uuid"),
                    from_zone=[zone.text for zone in entry.findall(".//from/member")],
                    to_zone=[zone.text for zone in entry.findall(".//to/member")],
                    source_address=[
                        src.text for src in entry.findall(".//source/member")
                    ],
                    destination_address=[
                        dest.text for dest in entry.findall(".//destination/member")
                    ],
                    destination_service=[
                        service.text for service in entry.findall(".//service/member")
                    ],
                    applications=[
                        application.text
                        for application in entry.findall(".//application/member")
                    ],
                    tags=[tag.text for tag in entry.findall(".//tag/member")],
                    action=action,
                    description=description,
                    log_setting=log_setting,
                    rule_number=rule_number_start + i,
                    scope=scope,
                    disabled=disabled_setting,
                    schedule=schedule,
                    devices=target_device_vsys,
                )
                self.parsed_config.security_rules.append(rule)
                #import ipdb;ipdb.set_trace()

    def _parse_nat_rules(self, root) -> None:
        for scope in self.rule_scopes:

            rules = root.findall(f".//{scope}/nat/rules/entry")
            rule_number_start = (len(self.parsed_config.nat_rules)) + 1

            for i, entry in enumerate(rules):
                description = (
                    entry.find(".//description").text
                    if entry.find(".//description") is not None
                    else None
                )
                disabled_setting = (
                    True
                    if (
                        entry.find(".//disabled") is not None
                        and entry.find(".//disabled").text == "yes"
                    )
                    else False
                )
                devices_settings = entry.findall(".//devices/entry")
                target_device_vsys = self._get_device_targets(devices_settings)

                translated_source_root = entry.find(
                    ".//source-translation//translated-address"
                )
                if translated_source_root is not None:
                    if translated_source_root.find(".//member") is not None:
                        translated_source = translated_source_root.find(
                            ".//member"
                        ).text
                    else:
                        translated_source = translated_source_root.text
                else:
                    translated_source = None

                translated_destination_root = entry.find(
                    ".//destination-translation//translated-address"
                )
                if translated_destination_root is not None:
                    if translated_destination_root.find(".//member"):
                        translated_destination = translated_destination_root.find(
                            ".//member"
                        ).text
                    else:
                        translated_destination = translated_destination_root.text
                else:
                    translated_destination = None

                destination_service = (
                    entry.find(".//service").text
                    if entry.find(".//service") is not None
                    else None
                )

                rule = Nat(
                    name=entry.get("name"),
                    uuid=entry.get("uuid"),
                    from_zone=[zone.text for zone in entry.findall(".//from/member")],
                    to_zone=[zone.text for zone in entry.findall(".//to/member")],
                    source_address=[
                        src.text for src in entry.findall(".//source/member")
                    ],
                    destination_address=[
                        dest.text for dest in entry.findall(".//destination/member")
                    ],
                    description=description,
                    rule_number=rule_number_start + i,
                    scope=scope,
                    disabled=disabled_setting,
                    translated_destination=translated_destination,
                    translated_source=translated_source,
                    destination_service=destination_service,
                    devices=target_device_vsys,
                )
                self.parsed_config.nat_rules.append(rule)

    def _parse_schedules(self, root: etree.Element) -> None:
        """Parse the schedule objects from the XML.

        Args:
            root (etree.Element): The root element of the XML.

        Returns:
            None
        """
        schedules = root.findall(".//schedule/entry")
        for entry in schedules:
            name = entry.get("name")
            description = (
                entry.find(".//description").text
                if entry.find(".//description") is not None
                else None
            )
            members = [member.text for member in entry.findall(".//member")]
            self.parsed_config.schedules.append(
                Schedule(name=name, description=description, members=members)
            )

    def _get_device_targets(
        self, devices_settings: List[etree.Element]
    ) -> List[Tuple[str, str]]:
        """Get the device targets from the devices settings.

        Args:
            devices_settings (List[etree.Element]): List of device settings.

        Returns:
            Dict[str, List[str]]: Dictionary mapping device names to a list of vsys values.
        """
        device_vsys_list = [] # List of tuples (device_id, vsys_id)
        for target_device in devices_settings:
            device = None
            vsys_settings = target_device.findall(".//vsys/entry")
            device_id = target_device.get("name")

            # Add the device to the list of devices if it is not already there
            for device_obj in self.parsed_config.devices:
                if device_obj.id == device_id:
                    device = device_obj
                    break
            if device is None:
                device = Device(id=device_id)
                self.parsed_config.devices.append(Device(id=device_id))
            
            # Add the vsys values to the device
            if device.vsys_ids is None:
                device.vsys_ids = set()
            for vs in vsys_settings:
                vsys_id = vs.get("name")
                device.vsys_ids.add(vsys_id)
                device_vsys_list.append((device_id, vsys_id))
        return device_vsys_list
