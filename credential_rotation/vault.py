import base64
import json
import os
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Optional


class VaultBackend(ABC):
    @abstractmethod
    def store(self, credential_id: str, secret_data: dict[str, str]) -> None: ...

    @abstractmethod
    def retrieve(self, credential_id: str) -> Optional[dict[str, str]]: ...

    @abstractmethod
    def delete(self, credential_id: str) -> bool: ...

    @abstractmethod
    def list_ids(self) -> list[str]: ...


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

    def __init__(self, vault_path: Optional[Path] = None, encryption_key: Optional[str] = None):
        self.vault_path = vault_path or (
            Path.home() / ".credential_rotation" / "vault_secrets.json"
        )
        self.vault_path.parent.mkdir(parents=True, exist_ok=True)
        self._key = encryption_key or os.environ.get("CREDROT_VAULT_KEY", "default-key-change-me")
        self._key_bytes = self._derive_key(self._key)

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
