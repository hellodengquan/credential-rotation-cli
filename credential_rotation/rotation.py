from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Tuple
from enum import Enum

from .models import Credential, CredentialStatus
from .storage import Storage


class RotationAction(str, Enum):
    ROTATE_NOW = "rotate_now"
    SCHEDULE_SOON = "schedule_soon"
    MONITOR = "monitor"
    NO_ACTION = "no_action"


CONCURRENT_ROTATION_WINDOW_DAYS = 1


@dataclass
class RotationConflict:
    credential_id: str
    conflicting_ids: List[str]
    service: Optional[str]
    details: str


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

    def detect_concurrent_rotation_conflicts(
        self,
        credentials: Optional[List[Credential]] = None,
        window_days: int = CONCURRENT_ROTATION_WINDOW_DAYS,
    ) -> List[RotationConflict]:
        creds = credentials or self.get_all_credentials()
        conflicts: List[RotationConflict] = []

        by_service: Dict[str, List[Credential]] = {}
        for cred in creds:
            if cred.status == CredentialStatus.ROTATED:
                continue
            svc = cred.service or "_no_service_"
            by_service.setdefault(svc, []).append(cred)

        for svc, svc_creds in by_service.items():
            if len(svc_creds) < 2:
                continue

            svc_creds_sorted = sorted(svc_creds, key=lambda c: c.expires_at)
            for i in range(len(svc_creds_sorted)):
                cred = svc_creds_sorted[i]
                conflicting: List[str] = []
                for j in range(len(svc_creds_sorted)):
                    if i == j:
                        continue
                    other = svc_creds_sorted[j]
                    delta_days = abs((cred.expires_at - other.expires_at).days)
                    if delta_days <= window_days:
                        conflicting.append(other.id)
                if conflicting:
                    details = (
                        f"同服务 {svc} 下有 {len(conflicting)} 个凭证到期时间差 <= {window_days} 天, "
                        f"并发轮换风险高 (建议间隔 > {window_days} 天)"
                    )
                    conflicts.append(RotationConflict(
                        credential_id=cred.id,
                        conflicting_ids=conflicting,
                        service=None if svc == "_no_service_" else svc,
                        details=details,
                    ))

        return conflicts

    def generate_rotation_list(
        self,
        include_expired: bool = True,
        include_expiring: bool = True,
        include_active: bool = False,
        check_conflicts: bool = True,
    ) -> List[Dict]:
        creds = self.get_all_credentials()
        now = datetime.now()
        rotation_list = []

        conflicts_map: Dict[str, RotationConflict] = {}
        if check_conflicts:
            for conf in self.detect_concurrent_rotation_conflicts(creds):
                conflicts_map[conf.credential_id] = conf

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
                conflict = conflicts_map.get(cred.id)
                entry = {
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
                    "service": cred.service or "",
                    "conflict": {
                        "has_conflict": True,
                        "conflicting_ids": conflict.conflicting_ids,
                        "details": conflict.details,
                    } if conflict else {
                        "has_conflict": False,
                        "conflicting_ids": [],
                        "details": "",
                    },
                }
                rotation_list.append(entry)

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
            "by_service": {},
            "conflicts": len(self.detect_concurrent_rotation_conflicts(creds)),
        }
        for cred in creds:
            status = cred.status.value
            if status in stats:
                stats[status] += 1
            if cred.type not in stats["by_type"]:
                stats["by_type"][cred.type] = 0
            stats["by_type"][cred.type] += 1
            svc = cred.service or "(未指定)"
            if svc not in stats["by_service"]:
                stats["by_service"][svc] = 0
            stats["by_service"][svc] += 1
        return stats
