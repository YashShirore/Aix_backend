import logging
import re
import uuid
from typing import Any, Dict, List, Optional

import netaddr
from ciscoconfparse import CiscoConfParse

from firewall_analyzer.models.firewall_models import (
    AddressGroup,
    AddressObject,
    FirewallConfiguration,
    Nat, Rule, ServiceGroup,
    ServiceObject, Device
)

from ..base import BaseParser


class CiscoASAParser(BaseParser):
    """
    Class for parsing text firewall configuration files.

    Attributes:
        input_files: List of text file paths to parse.
        parsed_config: The FirewallConfiguration object to store parsed data.
    """

    def parse_all(self) -> FirewallConfiguration:
        """Parse all necessary information."""
        self.file_contents = self._read_files(self.input_files)

        for fname, contents in self.file_contents.items():
            self._parse_device_info(contents)
            self._parse_address_objects(contents)
            self._parse_address_groups(contents)
            self._parse_service_objects(contents)
            self._parse_service_groups(contents)
            self._parse_security_rules(contents)
            self._parse_nat_rules(contents)
        return self.parsed_config

    def _read_files(self, input_files: List[str]) -> Dict[str, CiscoConfParse]:
        """Read the content of input files."""
        file_content = {}
        for input_file in input_files:
            try:
                file_content[input_file] = CiscoConfParse(input_file)
            except Exception as e:
                logging.error(f"Error reading file {input_file}: {e}")
        return file_content

    def _extract_hostname(self, content: CiscoConfParse) -> Optional[str]:
        hostname_obj = content.find_objects(r"^hostname")
        if hostname_obj:
            return hostname_obj[0].text.split()[1]

    def _extract_domain_name(self, content: CiscoConfParse) -> Optional[str]:
        domain_name_obj = content.find_objects(r"^domain-name")
        if domain_name_obj:
            return domain_name_obj[0].text.split()[1]

    def _extract_snmp_community(self, content: CiscoConfParse) -> Optional[str]:
        if snmp_obj := content.find_objects(r"^snmp-server host"):
            for obj in snmp_obj:
                community_string = None
                parts = obj.text.split()
                if 'community' in parts:
                    community_index = parts.index('community')
                    community_string = parts[community_index + 1]
                    return community_string

    def _extract_software_version(self, content: CiscoConfParse) -> Optional[str]:
        if soft_ver_obj := content.find_objects(r"^ASA Version"):
            for obj in soft_ver_obj:
                return obj.text.split()[-1]
            
    def _extract_serial_number(self, content: CiscoConfParse) -> Optional[str]:
        if ser_num_obj := content.find_objects(r": Serial Number:"):
            for obj in ser_num_obj:
                return obj.text.split()[-1]

    def _parse_device_info(self, content: CiscoConfParse) -> None:
        """Parse the system information."""

        hostname = self._extract_hostname(content)
        domain_name = self._extract_domain_name(content)
        snmp_community = self._extract_snmp_community(content)
        software_version = self._extract_software_version(content)
        serial_number = self._extract_serial_number(content)

        self.parsed_config.devices.append(Device(
            hostname=hostname, 
            domain_name=domain_name, 
            snmp_community=snmp_community, 
            software_version=software_version, 
            serial_number=serial_number
        ))

    def _parse_address_objects(self, content: CiscoConfParse) -> None:
        """Parse address objects from the configuration."""
        addr_objs = content.find_objects(r"^object network")
        all_rules = []
        for obj in addr_objs:
            object_name = obj.text.split()[-1]
            description = None
            netmask = None
            range_value = None
            fqdn = None
            nat_value = None
            for child in obj.children:
                if "description" in child.text:
                    description = self._extract_description(child.text)
                elif "host" in child.text:
                    netmask = child.text.split()[-1]
                elif "subnet" in child.text:
                    netmask = self._extract_subnet(child.text)
                elif "range" in child.text:
                    range_value = self._extract_range(child.text)
                elif "fqdn" in child.text:
                    fqdn = child.text.split()[-1]
                elif "nat" in child.text:
                    nat_value = self._extract_nat(child.text)
                else:
                    logging.error(f"Unknown object type: {child.text}")
            
            address_rule = AddressObject(
                name=object_name, 
                description=description,  
                netmask=netmask, 
                range=range_value,  
                fqdn=fqdn,  
                nat=nat_value,
            )
            
            all_rules.append(address_rule) 
        
        self.parsed_config.address_objects.extend(all_rules)

    def _extract_description(self, text: str) -> str:
        """Extract description from text."""
        return text.split("description", 1)[1].strip()

    def _extract_subnet(self, text: str) -> str:
        """Extract subnet from text."""
        parts = text.split()
        network = netaddr.IPNetwork(f"{parts[1]}/{parts[2]}")
        return str(network)

    def _extract_range(self, text: str) -> str:
        """Extract range from text."""
        parts = text.split()
        return f"{parts[1]}-{parts[2]}"
    
    def _extract_nat(self, text: str) -> str:
        """Extract NAT from text"""
        parts = text.split()
        return f"{parts[1:]}"  # Return NAT info

    def _parse_address_groups(self, content: CiscoConfParse) -> None:
        """Parse address groups from the configuration."""
        addr_groups = content.find_objects(r"^object-group network")
        for group in addr_groups:
            name = group.text.split()[-1]
            members = []
            description = None
            for child in group.children:
                if "description" in child.text:
                    description = child.text.split("description", 1)[1].strip()
                elif "network-object" in child.text or "group-object" in child.text:
                    members.append(child.text.split()[-1])
            self.parsed_config.address_groups.append(
                AddressGroup(name=name, members=members, description=description)
            )

    def _parse_service_objects(self, content: CiscoConfParse) -> None:
        """Parse service objects from the configuration."""
        service_objs = content.find_objects(r"^object service")

        for obj in service_objs:
            obj_args = {"name": obj.text.split()[-1]}
            for child in obj.children:
                if "description" in child.text:
                    obj_args["description"] = child.text.split("description", 1)[
                        1
                    ].strip()
                elif "service" in child.text:
                    parts = child.text.split()
                    obj_args["protocol"] = parts[1]
                    obj_args["src_or_dst"] = parts[2]
                    if parts[3] == "eq":
                        obj_args["port"] = parts[-1]
                    else:
                        logging.error(f"Unknown service object type: {child.text}")
            self.parsed_config.service_objects.append(ServiceObject(**obj_args))

    def _parse_service_groups(self, content: CiscoConfParse) -> None:
        """Parse service groups from the configuration."""
        service_groups = content.find_objects(r"^object-group service")
        for group in service_groups:
            name = group.text.split()[-1]
            members = []
            description = None
            for child in group.children:
                if "description" in child.text:
                    description = child.text.split("description", 1)[1].strip()
                elif "service-object" in child.text:
                    members.append(child.text.split()[-1])
            self.parsed_config.service_groups.append(
                ServiceGroup(name=name, members=members, description=description)
            )

    def _parse_security_rules(self, content: CiscoConfParse) -> None:
        """Parse security rules from the configuration."""
        acl_entries = content.find_objects(r"^access-list")

        for entry in acl_entries:
            rule = {
                "uuid": str(uuid.uuid4()),
                "source_address": [],
                "destination_address": [],
                "destination_service": [],
                "source_service": [],
                "description": "",
            }
            parts = entry.text.split()
            rule["name"] = parts[1]

            # Initialize action before checking further
            rule["action"] = None  # Initialize it to avoid missing field error

            if "remark" in parts:
                rule['description'] = entry.text.split('remark')[-1].strip()
                continue
            elif "extended" in parts:
                action = parts[3]
                rule["action"] = "allow" if action == "permit" else "deny"  # Assign "allow" or "deny"

                if parts[4] in ["udp", "tcp", "icmp"]:
                    rule["destination_service"].append(parts[4])
                    rule["source_address"].append(parts[5])
                    rule["destination_address"].append(parts[6])

            else:
                logging.error(f"Unknown ACL entry format: {entry.text}")
                continue

            # Only append to security_rules if "action" is set
            if rule["action"] is not None:
                self.parsed_config.security_rules.append(Rule(**rule))
            else:
                logging.error(f"Missing action for rule: {entry.text}")

    def _parse_nat_rules(self, content: CiscoConfParse) -> None:
        """Parse NAT rules from the configuration."""
        nat_objects = content.find_objects(r"^nat")

        # Initialize an empty list to store all the NAT rule objects.  
        all_rules = []  

        # Process each NAT object found.  
        for object in nat_objects:  
            # Initialize the attributes for the Nat object.  
            from_zone = []  
            to_zone = []  
            source_address = []  
            destination_address = []  
            translated_source = None  
            translated_destination = None
            destination_service = []
            description = None 
            
            # Split "object" text into a list of words, and store in var "parts".  
            parts = object.text.split()  

            # Update the attributes with the elements from the current object. 
            for i, element in enumerate(parts):  
                if element == 'nat':  
                    from_zone, to_zone = parts[i+1].strip("()").split(",")  

                elif element == 'source':  
                    # Handle both dynamic and static source NAT  
                    if parts[i + 1] == 'dynamic' or parts[i + 1] == 'static':  
                        source_address.append(parts[i + 2])  # Assuming 'real' address is the source address  
                        translated_source = parts[i + 3]     # Assuming this is the translated source  

                elif element == 'destination':  
                    destination_address.append(parts[i + 2])  # Assuming this is the destination address  
                    translated_destination = parts[i + 3]     # Assuming this is the translated destination  

                elif element == 'service':  
                    destination_service = parts[i + 2]  # Assuming this is the service  

                elif element == 'description':  
                    description = " ".join(parts[i+1:])  

            # Create a Nat object and append it to the all_rules list  
            nat_rule = Nat(  
                name="",  # Placeholder, as the name is not provided in the configuration. 
                uuid="",  # Placeholder, as the uuid is not provided in the configuration.
                from_zone=[from_zone],  
                to_zone=[to_zone],  
                source_address=source_address,  
                destination_address=destination_address,  
                translated_destination=translated_destination,  
                translated_source=translated_source,
                destination_service=destination_service,  
                description=description  
            )  
            all_rules.append(nat_rule)  

        # self.parsed_config.nat_rules is where we store the parsed Nat objects.
        self.parsed_config.nat_rules.extend(all_rules)
