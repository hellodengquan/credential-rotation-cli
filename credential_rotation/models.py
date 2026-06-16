import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Optional


class CredentialStatus(str, Enum):
    ACTIVE = "active"
    EXPIRING_SOON = "expiring_soon"
    EXPIRED = "expired"
    ROTATED = "rotated"


_DEFAULT_TYPE_CONFIGS: dict[str, dict[str, int]] = {
    "api_key": {"rotation_period_days": 90, "warning_days": 14},
    "password": {"rotation_period_days": 60, "warning_days": 7},
    "token": {"rotation_period_days": 30, "warning_days": 7},
    "certificate": {"rotation_period_days": 365, "warning_days": 30},
    "ssh_key": {"rotation_period_days": 180, "warning_days": 14},
    "oauth": {"rotation_period_days": 90, "warning_days": 14},
    "database_credential": {"rotation_period_days": 60, "warning_days": 7},
    "service_account": {"rotation_period_days": 90, "warning_days": 14},
}

TYPE_CONFIG_DESCRIPTIONS: dict[str, str] = {
    "api_key": "通用 API 密钥 (AK/SK)",
    "password": "账户密码，泄漏风险高",
    "token": "临时访问令牌 (JWT/OAuth)",
    "certificate": "SSL/TLS 证书，发布周期长",
    "ssh_key": "SSH 公私钥",
    "oauth": "OAuth 客户端凭据",
    "database_credential": "数据库账号/密码",
    "service_account": "云服务账号密钥",
}

CUSTOM_CONFIG_PATH = Path(
    os.environ.get(
        "CREDROT_TYPE_CONFIG", str(Path.home() / ".credential_rotation" / "type_configs.json")
    )
)


class TypeConfigRegistry:
    def __init__(self):
        self._configs: dict[str, dict[str, int]] = dict(_DEFAULT_TYPE_CONFIGS)
        self._custom_configs: dict[str, dict[str, int]] = {}
        self._custom_enabled: bool = True
        self._drain_mode: bool = False
        self._load_custom()

    def _load_custom(self) -> None:
        if CUSTOM_CONFIG_PATH.exists():
            try:
                with open(CUSTOM_CONFIG_PATH, encoding="utf-8") as f:
                    custom = json.load(f)
                if isinstance(custom, dict):
                    for k, v in custom.items():
                        if (
                            isinstance(v, dict)
                            and "rotation_period_days" in v
                            and "warning_days" in v
                        ):
                            cfg = {
                                "rotation_period_days": int(v["rotation_period_days"]),
                                "warning_days": int(v["warning_days"]),
                            }
                            self._custom_configs[k] = cfg
                            self._configs[k] = cfg
            except Exception:
                pass

    @property
    def custom_enabled(self) -> bool:
        return self._custom_enabled and not self._drain_mode

    @property
    def drain_mode(self) -> bool:
        return self._drain_mode

    def enable_custom(self) -> None:
        if not self._custom_enabled:
            self._custom_enabled = True
            for k, v in self._custom_configs.items():
                self._configs[k] = v

    def disable_custom(self, drain: bool = False) -> list[str]:
        removed: list[str] = []
        if drain:
            self._drain_mode = True
            return list(self._custom_configs.keys())
        self._custom_enabled = False
        for k in list(self._custom_configs.keys()):
            if k in self._configs:
                del self._configs[k]
                removed.append(k)
        return removed

    def reset_drain_mode(self) -> None:
        self._drain_mode = False

    def get(self, cred_type: str) -> dict[str, int]:
        if cred_type in self._configs:
            return self._configs[cred_type]
        if cred_type in self._custom_configs and self._drain_mode:
            return self._custom_configs[cred_type]
        return self._configs.get("api_key", {"rotation_period_days": 90, "warning_days": 14})

    def is_custom_type(self, cred_type: str) -> bool:
        return cred_type in self._custom_configs

    def is_draining_type(self, cred_type: str) -> bool:
        return self._drain_mode and self.is_custom_type(cred_type)

    def register(self, cred_type: str, rotation_period_days: int, warning_days: int) -> None:
        if self._drain_mode:
            raise RuntimeError(
                "Cannot register new types while in drain mode. Call reset_drain_mode() first."
            )
        cfg = {"rotation_period_days": rotation_period_days, "warning_days": warning_days}
        self._custom_configs[cred_type] = cfg
        if self._custom_enabled:
            self._configs[cred_type] = cfg

    def unregister(self, cred_type: str) -> bool:
        if cred_type in self._custom_configs:
            del self._custom_configs[cred_type]
            if cred_type in self._configs:
                del self._configs[cred_type]
            return True
        return False

    def save_custom(self) -> Path:
        CUSTOM_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(CUSTOM_CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(self._custom_configs, f, indent=2, ensure_ascii=False)
        return CUSTOM_CONFIG_PATH

    def list_all(self) -> dict[str, dict[str, int]]:
        return dict(self._configs)

    def list_custom(self) -> dict[str, dict[str, int]]:
        return dict(self._custom_configs)

    def list_draining(self) -> dict[str, dict[str, int]]:
        if not self._drain_mode:
            return {}
        return dict(self._custom_configs)


_type_registry = TypeConfigRegistry()


def get_type_config(cred_type: str) -> dict[str, int]:
    return _type_registry.get(cred_type)


def register_type_config(cred_type: str, rotation_period_days: int, warning_days: int) -> None:
    _type_registry.register(cred_type, rotation_period_days, warning_days)


def get_type_registry() -> TypeConfigRegistry:
    return _type_registry


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
    environment: Optional[str] = None
    secret_value: Optional[str] = None
    last_rotated_at: Optional[datetime] = None
    status: CredentialStatus = CredentialStatus.ACTIVE
    tags: list[str] = field(default_factory=list)

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
        data.setdefault("environment", None)
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
