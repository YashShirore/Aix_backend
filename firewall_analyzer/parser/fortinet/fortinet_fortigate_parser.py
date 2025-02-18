
# import logging
# import re
# import uuid
# from typing import Any, Dict, List, Optional

# import netaddr
# from ciscoconfparse import CiscoConfParse

# from firewall_analyzer.models.firewall_models import (
#     AddressGroup,
#     AddressObject,
#     FirewallConfiguration,
#     Nat, Rule, ServiceGroup,
#     ServiceObject, Device
# )

# from ..base import BaseParser

# class FortinetFortigateParser(BaseParser):
#     """
#     Class for parsing text firewall configuration files.

#     Attributes:
#         input_files: List of text file paths to parse.
#         parsed_config.: The FirewallConfiguration object to store parsed data.
#     """

#     def parse_all(self) -> FirewallConfiguration:
#         """Parse all necessary information."""
#         self.file_contents = self._read_files(self.input_files)

#         for fname, contents in self.file_contents.items():
#             #self._parse_device_info(contents)
#             self._parse_address_objects(contents)
#             #self._parse_address_groups(contents)
#             self._parse_service_objects(contents)
#             self._parse_service_groups(contents)
#             self._parse_security_rules(contents)
#             #self._parse_nat_rules(contents)
#         return self.parsed_config

#     def _read_files(self, input_files: List[str]) -> Dict[str, CiscoConfParse]:
#         """Read the content of input files."""
#         file_content = {}
#         for input_file in input_files:
#             try:
#                 file_content[input_file] = CiscoConfParse(input_file)
#             except Exception as e:
#                 logging.error(f"Error reading file {input_file}: {e}")
#         return file_content
        
#     def _parse_address_objects(self, content: CiscoConfParse) -> None:
#         """Parse address object from the configuration."""
#         addr_objs = content.find_objects(r"^config firewall address$")
        
#         for obj in addr_objs:
#             for entry in obj.children:
#                 if "next" in entry.text:
#                     continue

#                 rule_name = ' '.join(entry.text.split()[1:]).strip('"')
#                 address_object = AddressObject(name=rule_name)

#                 start_ip = None
#                 end_ip = None

#                 for child in entry.children:
#                     #if "set uuid" in child.text:
#                     #    address_object.uuid = child.text.split()[-1]
                    
#                     if "set type" in child.text:
#                         address_object.scope = child.text.split()[-1]

#                     elif "set comment" in child.text:
#                         description = ' '.join(child.text.split()[2:]) #TODO: description missing check, need to fix.
#                         address_object.description = None if description == '' else description

#                     #elif "set visibility" in child.text:
#                     #    address_object.visibility = child.text.split()[-1]

#                     #elif "set associated-interface" in child.text:
#                     #    address_object.associated_interface = child.text.split()[1:]

#                     #elif "set associated-interface" in child.text:
#                     #    address_object.associated_interface = ' '.join(child.text.split()[1:])

#                     elif "set start-ip" in child.text:
#                         start_ip = child.text.split()[-1]
                    
#                     elif "set end-ip" in child.text:
#                         end_ip = child.text.split()[-1]

#                     elif "set subnet" in child.text:
#                         address_object.netmask = f"{child.text.split()[-2]}/{child.text.split()[-1]}"
#                         break

#                     elif "set wildcard-fqdn" in child.text:
#                         address_object.fqdn = child.text.split()[-1]
#                         break

#                     elif "set fqdn" in child.text:
#                         address_object.fqdn = child.text.split()[-1]
#                         break
#                     #nat

#                 if start_ip and end_ip:
#                     address_object.range = f"{start_ip}-{end_ip}"

#                 self.parsed_config.address_objects.append(address_object)

#     def _parse_service_groups(self, content: CiscoConfParse) -> None:
#         import ipdb; ipdb.set_trace()
#         """Parse service objects from the configuration."""
#         import ipdb; ipdb.set_trace()
 
#         service_grp = content.find_objects(r"^config firewall service group$") #config firewall service category
 
#         for obj in service_grp:
#             for entry in obj.children:
 
#                 group_name = ' '.join(entry.text.split()[1:]).strip('"')
#                 service_group = ServiceGroup(name=group_name)
 
#                 if "next" in entry.text:
#                     continue
 
#                 for child in entry.children:
#                     if "set member" in child.text:
#                         members = child.text.split()[2:]
#                         members = [member.strip('"') for member in members]
#                         service_group.members = members
 
#                     elif "set comment" in child.text:
#                         description = ' '.join(child.text.split()[2:])
#                         service_group.description = None if description == '' else description #TODO: description missing check, need to fix.
 
#                 self.parsed_config.service_groups.append(service_group)


#     def _parse_service_objects(self, content: CiscoConfParse) -> None:
#         import ipdb; ipdb.set_trace()

#         """Parse service objects from the configuration."""
#         service_objs = content.find_objects(r"^config firewall service custom$")
#         for obj in service_objs:
#             for entry in obj.children:
 
#                 obj_name = ' '.join(entry.text.split()[1:]).strip('"')

#                 protocol = []
#                 port = []
#                 description = ""
 
#                 if "next" in entry.text:
#                     continue
 
#                 for child in entry.children:
#                     if "set protocol" in child.text: # discuss set protocol-number
#                         parts = child.text.replace("/", " ").split()
#                         protocol_info = parts[2:]
#                         protocol.extend(protocol_info)

#                     elif "set comment" in child.text:
#                         description = ' '.join(child.text.split()[2:])
#                         description = None if description == '' else description #TODO: description missing check, need to fix.

#                     elif "portrange" in child.text:
#                         port_info = child.text.split()[-1]
#                         if port_info.isdigit() or ('-' in port_info and all(part.isdigit() for part in port_info.split('-'))):
#                             #service_object.
#                             port.append(port_info)
#                             # discuss in standup.

#                         # , scope, tags, description, src_or_dst.
                
#                 service_object = ServiceObject(name=obj_name, protocol=protocol, description=description, port=port)
                
#                 self.parsed_config.service_objects.append(service_object)


#     def _parse_security_rules(self, content: CiscoConfParse) -> None:
#         """Parse security rules from the configuration."""
#         sec_objs = content.find_objects(r"^config firewall policy$")

#         import ipdb;ipdb.set_trace()

#         for obj in sec_objs:
#             for entry in obj.children:
#                 if "next" in entry.text:
#                     continue

#                 rule_number = entry.text.split()[-1]
#                 sec_rule_object = Rule(rule_number=int(rule_number))

#                 for child in entry.children:
#                     if "set name" in child.text:
#                         sec_rule_object.name = ' '.join(entry.text.split()[2:]).strip('"')

#                     elif "set uuid" in child.text:
#                         sec_rule_object.uuid = child.text.split()[-1]    

#                     elif "set srcintf" in child.text:
#                         sec_rule_object.from_zone = child.text.split().strip('"')[-1]

#                     elif "set dstintf" in child.text:
#                         sec_rule_object.to_zone = child.text.split().strip('"')[-1]

#                     elif "set srcaddr" in child.text:
#                         sec_rule_object.source_address = child.text.split().strip('"')[-1]

#                     elif "set dstaddr" in child.text:
#                         sec_rule_object.destination_address = child.text.split().strip('"')[-1]

#                     elif "set service" in child.text:
#                         sec_rule_object.destination_service = child.text.split().strip('"')[-1]  

#                     elif "set action" in child.text:
#                         sec_rule_object.action = child.text.split().strip[-1]

#                     elif "set comments" in child.text:
#                         #description = ' '.join(child.text.split()[2:]) # TODO: description missing check, need to fix.
#                         #sec_rule_object.description = None if description == '' else description
#                         comments = ' '.join(child.text.split()[2:])
#                         if comments == '':
#                             sec_rule_object.description = None
#                         else:
#                             sec_rule_object.description = comments

#                     elif "set logtraffic-start" in child.text:
#                         sec_rule_object.log_setting = child.text.split()[-1]
                    
#                     elif "set status" in child.text:
#                         status = child.text.split()[-1].strip()  # Extract the status
#                         if status == "enable":
#                             sec_rule_object.disabled = False
#                         elif status == "disabled":
#                             sec_rule_object.disabled = True

#                     elif "set schedule" in child.text:
#                         sec_rule_object.schedule =  child.text.split()[-1]

#                         # applications, tags, and devices pending.
                        
#                 self.parsed_config.security_rules.append(sec_rule_object)

# ---------------------------------------------------------------------------------------------------------
import logging
from typing import List, Dict, Optional

from ciscoconfparse import CiscoConfParse

from firewall_analyzer.models.firewall_models import (
    AddressGroup, AddressObject, FirewallConfiguration, Nat, Rule,
    ServiceGroup, ServiceObject, Device
)

from ..base import BaseParser

class FortinetFortigateParser(BaseParser):
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
            self._parse_address_objects(contents)
            self._parse_service_objects(contents)
            self._parse_service_groups(contents)
            self._parse_security_rules(contents)

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

    def _parse_address_objects(self, content: CiscoConfParse) -> None:
        """Parse address object from the configuration."""
        addr_objs = content.find_objects(r"^config firewall address$")
        
        for obj in addr_objs:
            for entry in obj.children:
                if "next" in entry.text:
                    continue

                rule_name = ' '.join(entry.text.split()[1:]).strip('"')
                address_object = AddressObject(name=rule_name)

                start_ip = self._extract_value_from_line(entry.text, "set start-ip")
                end_ip = self._extract_value_from_line(entry.text, "set end-ip")
                subnet = self._extract_value_from_line(entry.text, "set subnet")
                fqdn = self._extract_value_from_line(entry.text, "set fqdn")

                # Set values to the address object
                address_object.netmask = subnet
                address_object.range = f"{start_ip}-{end_ip}" if start_ip and end_ip else None
                address_object.fqdn = fqdn

                self.parsed_config.address_objects.append(address_object)

    def _parse_service_groups(self, content: CiscoConfParse) -> None:
        """Parse service groups from the configuration."""
        service_grp = content.find_objects(r"^config firewall service group$")
        
        for obj in service_grp:
            for entry in obj.children:
                group_name = ' '.join(entry.text.split()[1:]).strip('"')
                service_group = ServiceGroup(name=group_name)

                if "next" in entry.text:
                    continue

                for child in entry.children:
                    if "set member" in child.text:
                        members = child.text.split()[2:]
                        service_group.members = [member.strip('"') for member in members]

                    elif "set comment" in child.text:
                        description = ' '.join(child.text.split()[2:]).strip()
                        service_group.description = description if description else None

                self.parsed_config.service_groups.append(service_group)

    def _parse_service_objects(self, content: CiscoConfParse) -> None:
        """Parse service objects from the configuration."""
        service_objs = content.find_objects(r"^config firewall service custom$")
        
        for obj in service_objs:
            for entry in obj.children:
                obj_name = ' '.join(entry.text.split()[1:]).strip('"')

                protocol = []
                port = []
                description = ""

                if "next" in entry.text:
                    continue

                for child in entry.children:
                    if "set protocol" in child.text:
                        parts = child.text.replace("/", " ").split()
                        protocol_info = parts[2:]
                        protocol.extend(protocol_info)

                    elif "set comment" in child.text:
                        description = ' '.join(child.text.split()[2:]).strip()
                        description = description if description else None

                    elif "portrange" in child.text:
                        port_info = child.text.split()[-1]
                        if port_info.isdigit() or ('-' in port_info and all(part.isdigit() for part in port_info.split('-'))):
                            port.append(port_info)

                service_object = ServiceObject(name=obj_name, protocol=protocol, description=description, port=port)
                self.parsed_config.service_objects.append(service_object)

    def _parse_security_rules(self, content: CiscoConfParse) -> None:
        """Parse security rules from the configuration."""
        sec_objs = content.find_objects(r"^config firewall policy$")
        
        for obj in sec_objs:
            for entry in obj.children:
                if "next" in entry.text:
                    continue

                rule_number = entry.text.split()[-1]
                sec_rule_object = Rule(rule_number=int(rule_number))

                for child in entry.children:
                    if "set name" in child.text:
                        sec_rule_object.name = ' '.join(entry.text.split()[2:]).strip('"')

                    elif "set uuid" in child.text:
                        sec_rule_object.uuid = child.text.split()[-1]    

                    elif "set srcintf" in child.text:
                        sec_rule_object.from_zone = child.text.split().strip('"')[-1]

                    elif "set dstintf" in child.text:
                        sec_rule_object.to_zone = child.text.split().strip('"')[-1]

                    elif "set srcaddr" in child.text:
                        sec_rule_object.source_address = child.text.split().strip('"')[-1]

                    elif "set dstaddr" in child.text:
                        sec_rule_object.destination_address = child.text.split().strip('"')[-1]

                    elif "set service" in child.text:
                        sec_rule_object.destination_service = child.text.split().strip('"')[-1]  

                    elif "set action" in child.text:
                        sec_rule_object.action = child.text.split().strip()[-1]

                    elif "set comments" in child.text:
                        comments = ' '.join(child.text.split()[2:]).strip()
                        sec_rule_object.description = comments if comments else None

                    elif "set logtraffic-start" in child.text:
                        sec_rule_object.log_setting = child.text.split()[-1]
                    
                    elif "set status" in child.text:
                        status = child.text.split()[-1].strip()
                        sec_rule_object.disabled = (status == "disabled")

                    elif "set schedule" in child.text:
                        sec_rule_object.schedule = child.text.split()[-1]
                
                self.parsed_config.security_rules.append(sec_rule_object)

    def _extract_value_from_line(self, line: str, prefix: str) -> Optional[str]:
        """Helper method to extract a value from a line based on a prefix."""
        if line.startswith(prefix):
            return line.split()[-1]
        return None
