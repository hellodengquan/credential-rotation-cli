from datetime import datetime, timedelta
from typing import List, Optional, Dict
from enum import Enum

from .models import Credential, CredentialStatus
from .storage import Storage


class RotationAction(str, Enum):
    ROTATE_NOW = "rotate_now"
    SCHEDULE_SOON = "schedule_soon"
    MONITOR = "monitor"
    NO_ACTION = "no_action"


class RotationManager:
    def __init__(self, storage: Optional[Storage] = None):
        self.storage = storage or Storage()

    def get_all_credentials(self) -> List[Credential]:
        creds = self.storage.list_all()
        now = datetime.now()
        for cred in creds:
            if cred.status != CredentialStatus.ROTATED:
                cred.status = cred.get_status(now)
        return creds

    def get_expiring_credentials(self, within_days: Optional[int] = None) -> List[Credential]:
        creds = self.get_all_credentials()
        now = datetime.now()
        result = []
        for cred in creds:
            if cred.status == CredentialStatus.ROTATED:
                continue
            days_left = cred.days_until_expiry(now)
            if within_days is not None:
                if days_left <= within_days:
                    result.append(cred)
            else:
                if cred.is_expiring_soon(now) or cred.is_expired(now):
                    result.append(cred)
        result.sort(key=lambda c: c.expires_at)
        return result

    def get_expired_credentials(self) -> List[Credential]:
        creds = self.get_all_credentials()
        return [c for c in creds if c.status == CredentialStatus.EXPIRED]

    def get_action_for_credential(self, credential: Credential, now: Optional[datetime] = None) -> RotationAction:
        now = now or datetime.now()
        if credential.status == CredentialStatus.ROTATED:
            return RotationAction.NO_ACTION
        if credential.is_expired(now):
            return RotationAction.ROTATE_NOW
        days_left = credential.days_until_expiry(now)
        if days_left <= 7:
            return RotationAction.ROTATE_NOW
        if days_left <= credential.warning_days:
            return RotationAction.SCHEDULE_SOON
        return RotationAction.MONITOR

    def generate_rotation_list(self, include_expired: bool = True, include_expiring: bool = True,
                               include_active: bool = False) -> List[Dict]:
        creds = self.get_all_credentials()
        now = datetime.now()
        rotation_list = []

        for cred in creds:
            status = cred.status
            should_include = False

            if status == CredentialStatus.EXPIRED and include_expired:
                should_include = True
            elif status == CredentialStatus.EXPIRING_SOON and include_expiring:
                should_include = True
            elif status == CredentialStatus.ACTIVE and include_active:
                should_include = True

            if should_include:
                action = self.get_action_for_credential(cred, now)
                rotation_list.append({
                    "id": cred.id,
                    "name": cred.name,
                    "type": cred.type,
                    "owner": cred.owner or "",
                    "status": status.value,
                    "expires_at": cred.expires_at.isoformat(),
                    "days_until_expiry": cred.days_until_expiry(now),
                    "rotation_period_days": cred.rotation_period_days,
                    "warning_days": cred.warning_days,
                    "action": action.value,
                    "last_rotated_at": cred.last_rotated_at.isoformat() if cred.last_rotated_at else None,
                    "description": cred.description or "",
                    "tags": cred.tags,
                })

        rotation_list.sort(key=lambda x: x["expires_at"])
        return rotation_list

    def mark_as_rotated(self, credential_id: str) -> Credential:
        return self.storage.mark_rotated(credential_id)

    def add_credential(self, credential: Credential) -> Credential:
        return self.storage.add(credential)

    def get_credential(self, credential_id: str) -> Optional[Credential]:
        return self.storage.get_by_id(credential_id)

    def delete_credential(self, credential_id: str) -> bool:
        return self.storage.delete(credential_id)

    def get_statistics(self) -> Dict:
        creds = self.get_all_credentials()
        stats = {
            "total": len(creds),
            "active": 0,
            "expiring_soon": 0,
            "expired": 0,
            "rotated": 0,
            "by_type": {},
        }
        for cred in creds:
            status = cred.status.value
            if status in stats:
                stats[status] += 1
            if cred.type not in stats["by_type"]:
                stats["by_type"][cred.type] = 0
            stats["by_type"][cred.type] += 1
        return stats
