# Canonical event schema fields (reference) and helpers
from dataclasses import dataclass, field
from typing import Dict, Any, Optional

@dataclass
class Event:
    time: str
    src_ip: str = ""
    src_port: int = 0
    dst_ip: str = ""
    dst_port: int = 0
    proto: str = ""
    host: str = ""
    user: str = ""
    event_type: str = "other"   # auth_failed|conn|dns|process|other
    message: str = ""
    sourcetype: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)
