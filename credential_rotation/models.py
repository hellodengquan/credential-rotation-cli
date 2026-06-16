from dataclasses import dataclass, field, asdict
from datetime import datetime, date, timedelta
from typing import Optional, List
from enum import Enum


class CredentialStatus(str, Enum):
    ACTIVE = "active"
    EXPIRING_SOON = "expiring_soon"
    EXPIRED = "expired"
    ROTATED = "rotated"


@dataclass
class Credential:
    id: str
    name: str
    type: str
    created_at: datetime
    expires_at: datetime
    rotation_period_days: int = 90
    warning_days: int = 14
    description: Optional[str] = None
    owner: Optional[str] = None
    last_rotated_at: Optional[datetime] = None
    status: CredentialStatus = CredentialStatus.ACTIVE
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        data = asdict(self)
        data["status"] = self.status.value
        data["created_at"] = self.created_at.isoformat()
        data["expires_at"] = self.expires_at.isoformat()
        if self.last_rotated_at:
            data["last_rotated_at"] = self.last_rotated_at.isoformat()
        return data

    @classmethod
    def from_dict(cls, data: dict) -> "Credential":
        data = dict(data)
        data["status"] = CredentialStatus(data.get("status", "active"))
        data["created_at"] = datetime.fromisoformat(data["created_at"])
        data["expires_at"] = datetime.fromisoformat(data["expires_at"])
        if data.get("last_rotated_at"):
            data["last_rotated_at"] = datetime.fromisoformat(data["last_rotated_at"])
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
