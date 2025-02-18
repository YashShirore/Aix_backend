# Creates the models to structure the audit results, audit categories and priorities.

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class AuditCategory(Enum):
    """Enum representing different audit categories."""
    ADDRESS_OBJECTS = "Addresses"
    ADDRESS_GROUPS = "Address Grp"
    SERVICE_OBJECTS = "Services"
    SERVICE_GROUPS = "Service Grp"
    RULES = "Rules"
    NAT = "NAT"
    DEVICE = "Device"


class AuditPriority(Enum):
    """Enum representing different audit priorities."""
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"

class AuditGroup(Enum):
    """Enum representing different audit groups."""
    DUPLICATES = "Duplicates"
    UNUSED = "Unused"
    TEMP_KEYWORDS = "Temp Keywords"
    INSECURE_PROTOCOLS = "Insecure Protocols"
    EXPIRED_SCHEDULES = "Expired Schedules"
    OPEN_RULES = "Open Rules"

    def get_description(self):
        if self == AuditGroup.DUPLICATES:
            return 'Duplicates objects. This can lead to confusion and misconfiguration, produce inconsistent policy application, increased administrative overhead and increased resource consumption.'
        elif self == AuditGroup.UNUSED:
            return 'Unused objects that have been defined but are not in use. This can add administrative overhead.'
        elif self == AuditGroup.TEMP_KEYWORDS:
            return 'These keywords indicate it should only be used temporarily and should be removed after use. Temporary rules that have not been removed can lead to security vulnerabilities'
        elif self == AuditGroup.INSECURE_PROTOCOLS:
            return 'Insecure protocols that are being used. These protocols are considered insecure and should be replaced with more secure alternatives.'
        elif self == AuditGroup.EXPIRED_SCHEDULES:
            return 'Expired schedules that are no longer in use. These schedules should be removed to reduce complexity and administrative overhead'
        elif self == AuditGroup.OPEN_RULES:
            return 'Open rules that potentially allow traffic that is not required. These rules should be reviewed and removed if not required.'
        else:
            return 'No specific recommendation'
        
    def get_recommendation(self):
        if self == AuditGroup.DUPLICATES:
            return 'Duplicates should be removed across the rulebase.'
        elif self == AuditGroup.UNUSED:
            return 'Un-used objects should be removed.'
        elif self == AuditGroup.TEMP_KEYWORDS:
            return 'Temporary rules should be reviewed and removed if no longer required.'
        elif self == AuditGroup.INSECURE_PROTOCOLS:
            return 'Insecure protocols should be replaced with more secure alternatives.'
        elif self == AuditGroup.EXPIRED_SCHEDULES:
            return 'Expired schedules should be removed.'
        elif self == AuditGroup.OPEN_RULES:
            return 'Open rules should be reviewed and restricted if not required.'
        else:
            return 'No specific recommendation'
    

@dataclass
class AuditResult:
    """Class representing an audit result."""
    title: str
    category: AuditCategory
    description: str
    count: int
    raw_output: Any = field(default=None)
    priority: AuditPriority = field(default=None)
    show_raw_output: bool = field(default=False)
    recommendation: str = field(default=None)
    group: AuditGroup = field(default=None)
