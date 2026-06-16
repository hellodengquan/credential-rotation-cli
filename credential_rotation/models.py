from dataclasses import dataclass, field, asdict
from datetime import datetime, date, timedelta
from typing import Optional, List, Dict
from enum import Enum


class CredentialStatus(str, Enum):
    ACTIVE = "active"
    EXPIRING_SOON = "expiring_soon"
    EXPIRED = "expired"
    ROTATED = "rotated"


CREDENTIAL_TYPE_CONFIGS: Dict[str, Dict[str, int]] = {
    "api_key": {"rotation_period_days": 90, "warning_days": 14},
    "password": {"rotation_period_days": 60, "warning_days": 7},
    "token": {"rotation_period_days": 30, "warning_days": 7},
    "certificate": {"rotation_period_days": 365, "warning_days": 30},
    "ssh_key": {"rotation_period_days": 180, "warning_days": 14},
    "oauth": {"rotation_period_days": 90, "warning_days": 14},
    "database_credential": {"rotation_period_days": 60, "warning_days": 7},
    "service_account": {"rotation_period_days": 90, "warning_days": 14},
}


def get_type_config(cred_type: str) -> Dict[str, int]:
    return CREDENTIAL_TYPE_CONFIGS.get(cred_type, CREDENTIAL_TYPE_CONFIGS["api_key"])


SENSITIVE_FIELDS = {"secret_value"}


@dataclass
class Credential:
    id: str
    name: str
    type: str
    created_at: datetime
    expires_at: datetime
    rotation_period_days: int = 0
    warning_days: int = 0
    description: Optional[str] = None
    owner: Optional[str] = None
    service: Optional[str] = None
    secret_value: Optional[str] = None
    last_rotated_at: Optional[datetime] = None
    status: CredentialStatus = CredentialStatus.ACTIVE
    tags: List[str] = field(default_factory=list)

    def __post_init__(self):
        if self.rotation_period_days == 0:
            cfg = get_type_config(self.type)
            self.rotation_period_days = cfg["rotation_period_days"]
        if self.warning_days == 0:
            cfg = get_type_config(self.type)
            self.warning_days = cfg["warning_days"]

    def to_dict(self, include_sensitive: bool = False) -> dict:
        data = asdict(self)
        data["status"] = self.status.value
        data["created_at"] = self.created_at.isoformat()
        data["expires_at"] = self.expires_at.isoformat()
        if self.last_rotated_at:
            data["last_rotated_at"] = self.last_rotated_at.isoformat()
        if not include_sensitive:
            data.pop("secret_value", None)
        else:
            data["secret_value"] = self.secret_value
        return data

    @classmethod
    def from_dict(cls, data: dict) -> "Credential":
        data = dict(data)
        data["status"] = CredentialStatus(data.get("status", "active"))
        data["created_at"] = datetime.fromisoformat(data["created_at"])
        data["expires_at"] = datetime.fromisoformat(data["expires_at"])
        if data.get("last_rotated_at"):
            data["last_rotated_at"] = datetime.fromisoformat(data["last_rotated_at"])
        data.setdefault("secret_value", None)
        data.setdefault("service", None)
        rotation_period_days = data.get("rotation_period_days", 0)
        warning_days = data.get("warning_days", 0)
        if rotation_period_days == 0:
            cfg = get_type_config(data.get("type", "api_key"))
            data["rotation_period_days"] = cfg["rotation_period_days"]
        else:
            data["rotation_period_days"] = rotation_period_days
        if warning_days == 0:
            cfg = get_type_config(data.get("type", "api_key"))
            data["warning_days"] = cfg["warning_days"]
        else:
            data["warning_days"] = warning_days
        return cls(**data)

    def days_until_expiry(self, now: Optional[datetime] = None) -> int:
        now = now or datetime.now()
        delta = self.expires_at - now
        return delta.days

    def is_expired(self, now: Optional[datetime] = None) -> bool:
        now = now or datetime.now()
        return self.expires_at <= now

    def is_expiring_soon(self, now: Optional[datetime] = None) -> bool:
        now = now or datetime.now()
        days_left = self.days_until_expiry(now)
        return 0 <= days_left <= self.warning_days

    def get_status(self, now: Optional[datetime] = None) -> CredentialStatus:
        now = now or datetime.now()
        if self.status == CredentialStatus.ROTATED:
            return CredentialStatus.ROTATED
        if self.is_expired(now):
            return CredentialStatus.EXPIRED
        if self.is_expiring_soon(now):
            return CredentialStatus.EXPIRING_SOON
        return CredentialStatus.ACTIVE

    def rotation_window_start(self) -> datetime:
        return self.expires_at - timedelta(days=self.warning_days)
