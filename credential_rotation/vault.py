from abc import ABC, abstractmethod
from typing import Optional, List, Dict
from pathlib import Path
from datetime import datetime

from .models import Credential, CredentialStatus


class VaultBackend(ABC):
    @abstractmethod
    def store(self, credential_id: str, secret_data: Dict[str, str]) -> None:
        ...

    @abstractmethod
    def retrieve(self, credential_id: str) -> Optional[Dict[str, str]]:
        ...

    @abstractmethod
    def delete(self, credential_id: str) -> bool:
        ...

    @abstractmethod
    def list_ids(self) -> List[str]:
        ...


class FileVaultBackend(VaultBackend):
    def __init__(self, vault_path: Optional[Path] = None):
        self.vault_path = vault_path or (Path.home() / ".credential_rotation" / "vault.json")
        self.vault_path.parent.mkdir(parents=True, exist_ok=True)

    def _load(self) -> Dict[str, Dict[str, str]]:
        if not self.vault_path.exists():
            return {}
        import json
        with open(self.vault_path, "r", encoding="utf-8") as f:
            return json.load(f).get("secrets", {})

    def _save(self, secrets: Dict[str, Dict[str, str]]) -> None:
        import json
        data = {
            "version": "1.0",
            "updated_at": datetime.now().isoformat(),
            "secrets": secrets,
        }
        with open(self.vault_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def store(self, credential_id: str, secret_data: Dict[str, str]) -> None:
        secrets = self._load()
        secrets[credential_id] = secret_data
        self._save(secrets)

    def retrieve(self, credential_id: str) -> Optional[Dict[str, str]]:
        secrets = self._load()
        return secrets.get(credential_id)

    def delete(self, credential_id: str) -> bool:
        secrets = self._load()
        if credential_id not in secrets:
            return False
        del secrets[credential_id]
        self._save(secrets)
        return True

    def list_ids(self) -> List[str]:
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

    def store(self, credential_id: str, secret_data: Dict[str, str]) -> None:
        import json
        self._keyring.set_password(
            self.SERVICE_NAME, credential_id, json.dumps(secret_data)
        )

    def retrieve(self, credential_id: str) -> Optional[Dict[str, str]]:
        import json
        value = self._keyring.get_password(self.SERVICE_NAME, credential_id)
        if value is None:
            return None
        return json.loads(value)

    def delete(self, credential_id: str) -> bool:
        try:
            self._keyring.delete_password(self.SERVICE_NAME, credential_id)
            return True
        except self._keyring.errors.PasswordDeleteError:
            return False

    def list_ids(self) -> List[str]:
        try:
            return self._keyring.get_credential(self.SERVICE_NAME, None) or []
        except Exception:
            return []
