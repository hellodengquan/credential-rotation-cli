from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Optional

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
    conflicting_ids: list[str]
    service: Optional[str]
    environment: Optional[str]
    details: str


class RotationManager:
    def __init__(self, storage: Optional[Storage] = None):
        self.storage = storage or Storage()

    def get_all_credentials(self) -> list[Credential]:
        creds = self.storage.list_all()
        now = datetime.now()
        for cred in creds:
            if cred.status != CredentialStatus.ROTATED:
                cred.status = cred.get_status(now)
        return creds

    def get_expiring_credentials(self, within_days: Optional[int] = None) -> list[Credential]:
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

    def get_expired_credentials(self) -> list[Credential]:
        creds = self.get_all_credentials()
        return [c for c in creds if c.status == CredentialStatus.EXPIRED]

    def get_action_for_credential(
        self, credential: Credential, now: Optional[datetime] = None
    ) -> RotationAction:
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
        credentials: Optional[list[Credential]] = None,
        window_days: int = CONCURRENT_ROTATION_WINDOW_DAYS,
        cross_environment: bool = False,
    ) -> list[RotationConflict]:
        creds = credentials or self.get_all_credentials()
        conflicts: list[RotationConflict] = []

        if cross_environment:
            groups: dict[str, list[Credential]] = {}
            for cred in creds:
                if cred.status == CredentialStatus.ROTATED:
                    continue
                svc = cred.service or "_no_service_"
                groups.setdefault(svc, []).append(cred)
        else:
            groups = {}
            for cred in creds:
                if cred.status == CredentialStatus.ROTATED:
                    continue
                svc = cred.service or "_no_service_"
                env_val = cred.environment or "_no_env_"
                key = f"{svc}::{env_val}"
                groups.setdefault(key, []).append(cred)

        for group_key, group_creds in groups.items():
            if len(group_creds) < 2:
                continue

            svc_label: str
            env_label: Optional[str]
            if "::" in group_key:
                parts = group_key.split("::", 1)
                svc_label = parts[0]
                env_label = parts[1] if len(parts) > 1 else None
            else:
                svc_label = group_key
                env_label = None

            group_sorted = sorted(group_creds, key=lambda c: c.expires_at)
            for i in range(len(group_sorted)):
                cred = group_sorted[i]
                conflicting: list[str] = []
                for j in range(len(group_sorted)):
                    if i == j:
                        continue
                    other = group_sorted[j]
                    delta_days = abs((cred.expires_at - other.expires_at).days)
                    if delta_days <= window_days:
                        conflicting.append(other.id)
                if conflicting:
                    final_env = env_label if env_label and env_label != "_no_env_" else None
                    final_svc = svc_label if svc_label != "_no_service_" else None
                    details = (
                        f"同服务 {final_svc or '(未指定)'}"
                        + (f" 环境 {final_env}" if final_env else "")
                        + f" 下有 {len(conflicting)} 个凭证到期时间差 <= {window_days} 天, "
                        f"并发轮换风险高 (建议间隔 > {window_days} 天)"
                    )
                    conflicts.append(
                        RotationConflict(
                            credential_id=cred.id,
                            conflicting_ids=conflicting,
                            service=final_svc,
                            environment=final_env,
                            details=details,
                        )
                    )

        return conflicts

    def generate_rotation_list(
        self,
        include_expired: bool = True,
        include_expiring: bool = True,
        include_active: bool = False,
        check_conflicts: bool = True,
        cross_environment: bool = False,
    ) -> list[dict]:
        creds = self.get_all_credentials()
        now = datetime.now()
        rotation_list = []

        conflicts_map: dict[str, RotationConflict] = {}
        if check_conflicts:
            for conf in self.detect_concurrent_rotation_conflicts(
                creds, cross_environment=cross_environment
            ):
                conflicts_map[conf.credential_id] = conf

        for cred in creds:
            status = cred.status
            should_include = False

            if (
                (status == CredentialStatus.EXPIRED and include_expired)
                or (status == CredentialStatus.EXPIRING_SOON and include_expiring)
                or (status == CredentialStatus.ACTIVE and include_active)
            ):
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
                    "last_rotated_at": cred.last_rotated_at.isoformat()
                    if cred.last_rotated_at
                    else None,
                    "description": cred.description or "",
                    "tags": cred.tags,
                    "service": cred.service or "",
                    "environment": cred.environment or "",
                    "conflict": {
                        "has_conflict": True,
                        "conflicting_ids": conflict.conflicting_ids,
                        "details": conflict.details,
                    }
                    if conflict
                    else {
                        "has_conflict": False,
                        "conflicting_ids": [],
                        "details": "",
                    },
                }
                rotation_list.append(entry)

        rotation_list.sort(key=lambda x: str(x.get("expires_at", "")))
        return rotation_list

    def mark_as_rotated(self, credential_id: str) -> Credential:
        return self.storage.mark_rotated(credential_id)

    def add_credential(self, credential: Credential) -> Credential:
        return self.storage.add(credential)

    def get_credential(self, credential_id: str) -> Optional[Credential]:
        return self.storage.get_by_id(credential_id)

    def delete_credential(self, credential_id: str) -> bool:
        return self.storage.delete(credential_id)

    def get_statistics(self) -> dict[str, object]:
        creds = self.get_all_credentials()
        active = expiring_soon = expired = rotated = 0
        by_type: dict[str, int] = {}
        by_service: dict[str, int] = {}
        by_environment: dict[str, int] = {}
        for cred in creds:
            status = cred.status.value
            if status == "active":
                active += 1
            elif status == "expiring_soon":
                expiring_soon += 1
            elif status == "expired":
                expired += 1
            elif status == "rotated":
                rotated += 1
            by_type[cred.type] = by_type.get(cred.type, 0) + 1
            svc = cred.service or "(未指定)"
            by_service[svc] = by_service.get(svc, 0) + 1
            env = cred.environment or "(未指定)"
            by_environment[env] = by_environment.get(env, 0) + 1
        return {
            "total": len(creds),
            "active": active,
            "expiring_soon": expiring_soon,
            "expired": expired,
            "rotated": rotated,
            "by_type": by_type,
            "by_service": by_service,
            "by_environment": by_environment,
            "conflicts": len(self.detect_concurrent_rotation_conflicts(creds)),
        }
