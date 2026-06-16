import base64
import getpass
import json
import os
import pwd
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional


class IdentityType(str, Enum):
    ROOT = "root"
    SERVICE_ACCOUNT = "service_account"
    REGULAR_USER = "regular_user"
    UNKNOWN = "unknown"


def detect_identity() -> IdentityType:
    try:
        uid = os.getuid()
    except AttributeError:
        return IdentityType.UNKNOWN
    if uid == 0:
        return IdentityType.ROOT
    try:
        user = getpass.getuser()
    except Exception:
        return IdentityType.UNKNOWN
    service_account_names = {
        "www-data",
        "nginx",
        "apache",
        "nobody",
        "postgres",
        "mysql",
        "redis",
        "daemon",
        "systemd-network",
        "systemd-resolve",
        "syslog",
        "_www",
        "www",
    }
    if user in service_account_names or user.startswith("_"):
        return IdentityType.SERVICE_ACCOUNT
    if user.lower().startswith("svc-") or user.lower().startswith("service-"):
        return IdentityType.SERVICE_ACCOUNT
    try:
        pw = pwd.getpwuid(uid)
        shell = pw.pw_shell
        if shell in ("", "/usr/sbin/nologin", "/bin/false", "/sbin/nologin"):
            return IdentityType.SERVICE_ACCOUNT
    except Exception:
        pass
    return IdentityType.REGULAR_USER


def get_vault_fallback_path(identity: Optional[IdentityType] = None) -> Path:
    if identity is None:
        identity = detect_identity()
    if identity == IdentityType.ROOT:
        return Path("/var/lib/credential-rotation/vault_secrets.json")
    if identity == IdentityType.SERVICE_ACCOUNT:
        try:
            return Path(f"/var/lib/credential-rotation/{getpass.getuser()}/vault_secrets.json")
        except Exception:
            return Path("/var/lib/credential-rotation/service/vault_secrets.json")
    return Path.home() / ".credential_rotation" / "vault_secrets.json"


def get_vault_key_for_identity(identity: Optional[IdentityType] = None) -> Optional[str]:
    if identity is None:
        identity = detect_identity()
    env_keys = [
        "CREDROT_VAULT_KEY",
        "CREDROT_SECRET_KEY",
    ]
    if identity == IdentityType.ROOT:
        env_keys = ["CREDROT_VAULT_KEY_ROOT", *env_keys]
    elif identity == IdentityType.SERVICE_ACCOUNT:
        env_keys = ["CREDROT_VAULT_KEY_SVC", *env_keys]
    for key in env_keys:
        val = os.environ.get(key)
        if val:
            return val
    if identity == IdentityType.ROOT:
        root_key_path = Path("/var/lib/credential-rotation/.vault_key")
        if root_key_path.exists() and root_key_path.stat().st_mode & 0o777 == 0o600:
            try:
                return root_key_path.read_text(encoding="utf-8").strip()
            except Exception:
                pass
    return None


@dataclass
class RotationTemplate:
    credential_id: str
    rotation_period_days: int
    last_rotated_at: Optional[datetime] = None
    next_rotation_at: Optional[datetime] = None
    rotation_lambda: Optional[str] = None
    rotation_schedule: Optional[str] = None
    enabled: bool = False
    backend: Optional[str] = None


class VaultBackend(ABC):
    @abstractmethod
    def store(self, credential_id: str, secret_data: dict[str, str]) -> None: ...

    @abstractmethod
    def retrieve(self, credential_id: str) -> Optional[dict[str, str]]: ...

    @abstractmethod
    def delete(self, credential_id: str) -> bool: ...

    @abstractmethod
    def list_ids(self) -> list[str]: ...

    def create_rotation_template(
        self,
        credential_id: str,
        rotation_period_days: int,
        rotation_lambda: Optional[str] = None,
        **kwargs,
    ) -> RotationTemplate:
        raise NotImplementedError(f"{self.__class__.__name__} does not support rotation templates")

    def describe_rotation(self, credential_id: str) -> Optional[RotationTemplate]:
        raise NotImplementedError(f"{self.__class__.__name__} does not support rotation templates")

    def disable_rotation(self, credential_id: str) -> bool:
        raise NotImplementedError(f"{self.__class__.__name__} does not support rotation templates")

    def rotate_secret(self, credential_id: str, **kwargs) -> bool:
        raise NotImplementedError(f"{self.__class__.__name__} does not support secret rotation")

    def supports_rotation(self) -> bool:
        base_methods = [
            "create_rotation_template",
            "describe_rotation",
            "disable_rotation",
            "rotate_secret",
        ]
        for method_name in base_methods:
            base_method = getattr(VaultBackend, method_name, None)
            cls_method = getattr(self.__class__, method_name, None)
            if base_method is None or cls_method is None:
                return False
            if cls_method is base_method:
                return False
        return True


class FileVaultBackend(VaultBackend):
    def __init__(self, vault_path: Optional[Path] = None):
        self.vault_path = vault_path or (Path.home() / ".credential_rotation" / "vault.json")
        self.vault_path.parent.mkdir(parents=True, exist_ok=True)

    def _load(self) -> dict[str, dict[str, str]]:
        if not self.vault_path.exists():
            return {}
        with open(self.vault_path, encoding="utf-8") as f:
            return json.load(f).get("secrets", {})  # type: ignore[no-any-return]

    def _save(self, secrets: dict[str, dict[str, str]]) -> None:
        data = {
            "version": "1.0",
            "updated_at": datetime.now().isoformat(),
            "secrets": secrets,
        }
        with open(self.vault_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def store(self, credential_id: str, secret_data: dict[str, str]) -> None:
        secrets = self._load()
        secrets[credential_id] = secret_data
        self._save(secrets)

    def retrieve(self, credential_id: str) -> Optional[dict[str, str]]:
        secrets = self._load()
        return secrets.get(credential_id)

    def delete(self, credential_id: str) -> bool:
        secrets = self._load()
        if credential_id not in secrets:
            return False
        del secrets[credential_id]
        self._save(secrets)
        return True

    def list_ids(self) -> list[str]:
        secrets = self._load()
        return list(secrets.keys())


class KeyringVaultBackend(VaultBackend):
    SERVICE_NAME = "credential-rotation"

    def __init__(self) -> None:
        try:
            import keyring

            self._keyring = keyring
        except ImportError:
            raise ImportError(
                "keyring package is required for KeyringVaultBackend. "
                "Install with: pip install keyring"
            )

    def store(self, credential_id: str, secret_data: dict[str, str]) -> None:
        self._keyring.set_password(self.SERVICE_NAME, credential_id, json.dumps(secret_data))

    def retrieve(self, credential_id: str) -> Optional[dict[str, str]]:
        value = self._keyring.get_password(self.SERVICE_NAME, credential_id)
        if value is None:
            return None
        return json.loads(value)  # type: ignore[no-any-return]

    def delete(self, credential_id: str) -> bool:
        try:
            self._keyring.delete_password(self.SERVICE_NAME, credential_id)
            return True
        except self._keyring.errors.PasswordDeleteError:
            return False

    def list_ids(self) -> list[str]:
        try:
            result = self._keyring.get_credential(self.SERVICE_NAME, None)
            if isinstance(result, list):
                return result
            return []
        except Exception:
            return []


class EnvFileVaultBackend(VaultBackend):
    _ENCODING = "utf-8"

    def __init__(
        self,
        vault_path: Optional[Path] = None,
        encryption_key: Optional[str] = None,
        identity: Optional[IdentityType] = None,
    ):
        if vault_path is None:
            vault_path = get_vault_fallback_path(identity)
        self.vault_path = vault_path
        self.vault_path.parent.mkdir(parents=True, exist_ok=True)
        if encryption_key is None:
            encryption_key = get_vault_key_for_identity(identity)
        self._key = encryption_key or "default-key-change-me"
        self._key_bytes = self._derive_key(self._key)
        self._identity = identity or detect_identity()

    @staticmethod
    def _derive_key(key: str) -> bytes:
        import hashlib

        return hashlib.sha256(key.encode("utf-8")).digest()

    def _xor_cipher(self, data: bytes) -> bytes:
        key = self._key_bytes
        return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

    def _load(self) -> dict[str, str]:
        if not self.vault_path.exists():
            return {}
        with open(self.vault_path, encoding="utf-8") as f:
            data = json.load(f)
        result = {}
        for k, v in data.get("secrets", {}).items():
            try:
                decrypted = self._xor_cipher(base64.b64decode(v))
                result[k] = decrypted.decode(self._ENCODING)
            except Exception:
                result[k] = v
        return result

    def _save(self, secrets: dict[str, str]) -> None:
        encoded = {}
        for k, v in secrets.items():
            encrypted = self._xor_cipher(v.encode(self._ENCODING))
            encoded[k] = base64.b64encode(encrypted).decode("ascii")
        data = {
            "version": "1.0",
            "backend": "envfile",
            "updated_at": datetime.now().isoformat(),
            "secrets": encoded,
        }
        with open(self.vault_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def store(self, credential_id: str, secret_data: dict[str, str]) -> None:
        secrets = self._load()
        secrets[credential_id] = json.dumps(secret_data)
        self._save(secrets)

    def retrieve(self, credential_id: str) -> Optional[dict[str, str]]:
        secrets = self._load()
        raw = secrets.get(credential_id)
        if raw is None:
            return None
        try:
            return json.loads(raw)  # type: ignore[no-any-return]
        except json.JSONDecodeError:
            return {"value": raw}

    def delete(self, credential_id: str) -> bool:
        secrets = self._load()
        if credential_id not in secrets:
            return False
        del secrets[credential_id]
        self._save(secrets)
        return True

    def list_ids(self) -> list[str]:
        return list(self._load().keys())


class AWSSecretsManagerBackend(VaultBackend):
    def __init__(
        self,
        region: Optional[str] = None,
        prefix: str = "credrot/",
    ):
        try:
            import boto3

            self._boto3 = boto3
        except ImportError:
            raise ImportError(
                "boto3 is required for AWSSecretsManagerBackend. Install with: pip install boto3"
            )
        self.region = region or os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
        self.prefix = prefix
        self._client = None

    def _get_client(self):
        if self._client is None:
            self._client = self._boto3.client("secretsmanager", region_name=self.region)
        return self._client

    def _secret_name(self, credential_id: str) -> str:
        return f"{self.prefix}{credential_id}"

    def store(self, credential_id: str, secret_data: dict[str, str]) -> None:
        client = self._get_client()
        name = self._secret_name(credential_id)
        secret_string = json.dumps(secret_data)
        try:
            client.put_secret_value(
                SecretId=name,
                SecretString=secret_string,
            )
        except client.exceptions.ResourceNotFoundException:
            client.create_secret(
                Name=name,
                SecretString=secret_string,
                Description=f"Credential rotation secret for {credential_id}",
            )

    def retrieve(self, credential_id: str) -> Optional[dict[str, str]]:
        client = self._get_client()
        name = self._secret_name(credential_id)
        try:
            response = client.get_secret_value(SecretId=name)
            return json.loads(response["SecretString"])  # type: ignore[no-any-return]
        except client.exceptions.ResourceNotFoundException:
            return None
        except Exception:
            return None

    def delete(self, credential_id: str) -> bool:
        client = self._get_client()
        name = self._secret_name(credential_id)
        try:
            client.delete_secret(
                SecretId=name,
                RecoveryWindowInDays=7,
            )
            return True
        except client.exceptions.ResourceNotFoundException:
            return False
        except Exception:
            return False

    def list_ids(self) -> list[str]:
        client = self._get_client()
        ids = []
        try:
            paginator = client.get_paginator("list_secrets")
            for page in paginator.paginate(
                Filters=[{"Key": "name-prefix", "Values": [self.prefix]}]
            ):
                for secret in page.get("SecretList", []):
                    name = secret["Name"]
                    if name.startswith(self.prefix):
                        ids.append(name[len(self.prefix) :])
        except Exception:
            pass
        return ids

    def create_rotation_template(
        self,
        credential_id: str,
        rotation_period_days: int,
        rotation_lambda: Optional[str] = None,
        **kwargs,
    ) -> RotationTemplate:
        client = self._get_client()
        name = self._secret_name(credential_id)
        rotate_kwargs: dict = {"SecretId": name}
        if rotation_lambda:
            rotate_kwargs["RotationLambdaARN"] = rotation_lambda
        rotate_kwargs["RotationRules"] = {"AutomaticallyAfterDays": rotation_period_days}
        try:
            client.rotate_secret(**rotate_kwargs)
        except client.exceptions.ResourceNotFoundException:
            raise ValueError(f"Secret '{credential_id}' not found")
        return self.describe_rotation(credential_id) or RotationTemplate(
            credential_id=credential_id,
            rotation_period_days=rotation_period_days,
            rotation_lambda=rotation_lambda,
            enabled=True,
            backend="aws",
        )

    def describe_rotation(self, credential_id: str) -> Optional[RotationTemplate]:
        client = self._get_client()
        name = self._secret_name(credential_id)
        try:
            secret = client.describe_secret(SecretId=name)
            rotation_enabled = secret.get("RotationEnabled", False)
            rotation_rules = secret.get("RotationRules", {})
            last_rotated = secret.get("LastRotatedDate")
            next_rotation = secret.get("NextRotationDate")

            def _to_dt(val):
                if val and isinstance(val, datetime):
                    if val.tzinfo is None:
                        val = val.replace(tzinfo=timezone.utc)
                    return val
                return None

            return RotationTemplate(
                credential_id=credential_id,
                rotation_period_days=rotation_rules.get("AutomaticallyAfterDays", 0),
                last_rotated_at=_to_dt(last_rotated),
                next_rotation_at=_to_dt(next_rotation),
                rotation_lambda=secret.get("RotationLambdaARN"),
                enabled=bool(rotation_enabled),
                backend="aws",
            )
        except client.exceptions.ResourceNotFoundException:
            return None
        except Exception:
            return None

    def disable_rotation(self, credential_id: str) -> bool:
        client = self._get_client()
        name = self._secret_name(credential_id)
        try:
            client.cancel_rotate_secret(SecretId=name)
            return True
        except client.exceptions.ResourceNotFoundException:
            return False
        except Exception:
            return False

    def rotate_secret(self, credential_id: str, **kwargs) -> bool:
        client = self._get_client()
        name = self._secret_name(credential_id)
        try:
            client.rotate_secret(SecretId=name)
            return True
        except client.exceptions.ResourceNotFoundException:
            return False
        except Exception:
            return False


class GCPSecretManagerBackend(VaultBackend):
    def __init__(
        self,
        project_id: Optional[str] = None,
        prefix: str = "credrot-",
    ):
        try:
            from google.cloud import secretmanager

            self._secretmanager = secretmanager
        except ImportError:
            raise ImportError(
                "google-cloud-secret-manager is required for GCPSecretManagerBackend. "
                "Install with: pip install google-cloud-secret-manager"
            )
        self.project_id = project_id or os.environ.get("GCP_PROJECT_ID", "")
        if not self.project_id:
            raise ValueError("GCP project_id must be provided or set GCP_PROJECT_ID env var")
        self.prefix = prefix
        self._client = None

    def _get_client(self):
        if self._client is None:
            self._client = self._secretmanager.SecretManagerServiceClient()
        return self._client

    def _parent(self) -> str:
        return f"projects/{self.project_id}"

    def _secret_path(self, credential_id: str) -> str:
        return f"{self._parent()}/secrets/{self.prefix}{credential_id}"

    def _secret_version_path(self, credential_id: str, version: str = "latest") -> str:
        return f"{self._secret_path(credential_id)}/versions/{version}"

    def store(self, credential_id: str, secret_data: dict[str, str]) -> None:
        client = self._get_client()
        secret_id = f"{self.prefix}{credential_id}"
        payload = json.dumps(secret_data).encode("utf-8")

        try:
            client.get_secret(name=self._secret_path(credential_id))
        except Exception:
            client.create_secret(
                parent=self._parent(),
                secret_id=secret_id,
                replication={"automatic": {}},
            )

        client.add_secret_version(
            parent=self._secret_path(credential_id),
            payload={"data": payload},
        )

    def retrieve(self, credential_id: str) -> Optional[dict[str, str]]:
        client = self._get_client()
        try:
            response = client.access_secret_version(name=self._secret_version_path(credential_id))
            return json.loads(response.payload.data.decode("utf-8"))  # type: ignore[no-any-return]
        except Exception:
            return None

    def delete(self, credential_id: str) -> bool:
        client = self._get_client()
        try:
            client.delete_secret(name=self._secret_path(credential_id))
            return True
        except Exception:
            return False

    def list_ids(self) -> list[str]:
        client = self._get_client()
        ids = []
        try:
            for secret in client.list_secrets(parent=self._parent()):
                name = secret.name.rsplit("/", 1)[-1]
                if name.startswith(self.prefix):
                    ids.append(name[len(self.prefix) :])
        except Exception:
            pass
        return ids

    def _get_label(self, secret, key: str) -> Optional[str]:
        labels = getattr(secret, "labels", None) or {}
        if isinstance(labels, dict):
            return str(labels.get(key, "")) or None
        return None

    def _update_labels(self, credential_id: str, labels: dict[str, str]) -> None:
        from google.protobuf import field_mask_pb2

        client = self._get_client()
        path = self._secret_path(credential_id)
        secret = client.get_secret(name=path)
        current_labels = dict(getattr(secret, "labels", {}) or {})
        current_labels.update(labels)
        secret.labels = current_labels
        update_mask = field_mask_pb2.FieldMask(paths=["labels"])
        client.update_secret(secret=secret, update_mask=update_mask)

    def create_rotation_template(
        self,
        credential_id: str,
        rotation_period_days: int,
        rotation_lambda: Optional[str] = None,
        **kwargs,
    ) -> RotationTemplate:
        labels = {
            "credrot_rotation_days": str(rotation_period_days),
            "credrot_rotation_enabled": "true",
        }
        if rotation_lambda:
            labels["credrot_rotation_target"] = rotation_lambda
        self._update_labels(credential_id, labels)
        client = self._get_client()
        path = self._secret_path(credential_id)
        secret = client.get_secret(name=path)
        create_time = getattr(secret, "create_time", None)
        last_rotated = None
        if create_time:
            last_rotated = create_time
        return RotationTemplate(
            credential_id=credential_id,
            rotation_period_days=rotation_period_days,
            last_rotated_at=last_rotated,
            rotation_lambda=rotation_lambda,
            enabled=True,
            backend="gcp",
        )

    def describe_rotation(self, credential_id: str) -> Optional[RotationTemplate]:
        client = self._get_client()
        try:
            secret = client.get_secret(name=self._secret_path(credential_id))
            labels = dict(getattr(secret, "labels", {}) or {})
            enabled = labels.get("credrot_rotation_enabled", "") == "true"
            period_days = int(labels.get("credrot_rotation_days", "0") or "0")
            rotation_target = labels.get("credrot_rotation_target")
            create_time = getattr(secret, "create_time", None)
            last_rotated = None
            next_rotation = None
            if create_time and period_days > 0:
                from datetime import timedelta

                last_rotated = create_time
                next_rotation = create_time + timedelta(days=period_days)
            return RotationTemplate(
                credential_id=credential_id,
                rotation_period_days=period_days,
                last_rotated_at=last_rotated,
                next_rotation_at=next_rotation,
                rotation_lambda=rotation_target,
                enabled=enabled,
                backend="gcp",
            )
        except Exception:
            return None

    def disable_rotation(self, credential_id: str) -> bool:
        try:
            self._update_labels(credential_id, {"credrot_rotation_enabled": "false"})
            return True
        except Exception:
            return False

    def rotate_secret(self, credential_id: str, **kwargs) -> bool:
        new_value = kwargs.get("new_value")
        if new_value is None:
            existing = self.retrieve(credential_id)
            if existing is None:
                return False
            import secrets

            new_data = dict(existing)
            for key in new_data:
                if key in ("password", "secret", "api_key", "token", "value"):
                    new_data[key] = secrets.token_urlsafe(32)
                    break
            new_value = json.dumps(new_data).encode("utf-8")
        elif isinstance(new_value, str):
            new_value = new_value.encode("utf-8")
        client = self._get_client()
        try:
            client.add_secret_version(
                parent=self._secret_path(credential_id),
                payload={"data": new_value},
            )
            return True
        except Exception:
            return False


VAULT_BACKENDS: dict[str, type[VaultBackend]] = {
    "file": FileVaultBackend,
    "keyring": KeyringVaultBackend,
    "envfile": EnvFileVaultBackend,
    "aws": AWSSecretsManagerBackend,
    "gcp": GCPSecretManagerBackend,
}


def get_vault_backend(name: str, **kwargs) -> VaultBackend:
    cls = VAULT_BACKENDS.get(name)
    if cls is None:
        raise ValueError(
            f"Unknown vault backend '{name}'. Available: {', '.join(VAULT_BACKENDS.keys())}"
        )
    return cls(**kwargs)
