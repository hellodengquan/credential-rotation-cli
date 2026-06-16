import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from .models import SENSITIVE_FIELDS, Credential, CredentialStatus

DEFAULT_STORAGE_PATH = Path.home() / ".credential_rotation" / "credentials.json"


def _encrypt_field(value: str, credential_id: str, field_name: str) -> str:
    try:
        import keyring

        keyring.set_password(
            "credential-rotation",
            f"{credential_id}:{field_name}",
            value,
        )
        return f"ENCRYPTED:{credential_id}:{field_name}"
    except Exception:
        return value


def _decrypt_field(stored_value: str) -> str:
    if not stored_value.startswith("ENCRYPTED:"):
        return stored_value
    try:
        import keyring

        parts = stored_value.split(":", 2)
        if len(parts) == 3:
            return (
                keyring.get_password("credential-rotation", f"{parts[1]}:{parts[2]}")
                or stored_value
            )
    except Exception:
        pass
    return stored_value


def _is_encrypted(value: str) -> bool:
    return isinstance(value, str) and value.startswith("ENCRYPTED:")


class Storage:
    def __init__(
        self,
        storage_path: Optional[Path] = None,
        use_keyring: bool = False,
    ):
        self.storage_path = storage_path or DEFAULT_STORAGE_PATH
        self.use_keyring = use_keyring
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)

    def _load_all(self) -> list[dict]:
        if not self.storage_path.exists():
            return []
        with open(self.storage_path, encoding="utf-8") as f:
            data = json.load(f)
        return data.get("credentials", [])  # type: ignore[no-any-return]

    def _save_all(self, credentials: list[Credential]):
        items = []
        for c in credentials:
            d = c.to_dict(include_sensitive=True)
            if self.use_keyring:
                for field_name in SENSITIVE_FIELDS:
                    val = d.get(field_name)
                    if val and not _is_encrypted(str(val)):
                        d[field_name] = _encrypt_field(str(val), c.id, field_name)
            else:
                for field_name in SENSITIVE_FIELDS:
                    d.pop(field_name, None)
            items.append(d)

        data = {
            "version": "1.0",
            "encrypted": self.use_keyring,
            "updated_at": datetime.now().isoformat(),
            "credentials": items,
        }
        with open(self.storage_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def _decrypt_credential(self, raw: dict) -> dict:
        raw = dict(raw)
        for field_name in SENSITIVE_FIELDS:
            val = raw.get(field_name)
            if val and _is_encrypted(str(val)):
                raw[field_name] = _decrypt_field(str(val))
        return raw

    def list_all(self) -> list[Credential]:
        raw = self._load_all()
        result = []
        for item in raw:
            if self.use_keyring:
                item = self._decrypt_credential(item)
            result.append(Credential.from_dict(item))
        return result

    def get_by_id(self, credential_id: str) -> Optional[Credential]:
        for cred in self.list_all():
            if cred.id == credential_id:
                return cred
        return None

    def add(self, credential: Credential) -> Credential:
        existing = self.get_by_id(credential.id)
        if existing:
            raise ValueError(f"Credential with id '{credential.id}' already exists")
        credentials = self.list_all()
        credentials.append(credential)
        self._save_all(credentials)
        return credential

    def update(self, credential: Credential) -> Credential:
        credentials = self.list_all()
        found = False
        for i, cred in enumerate(credentials):
            if cred.id == credential.id:
                credentials[i] = credential
                found = True
                break
        if not found:
            raise ValueError(f"Credential with id '{credential.id}' not found")
        self._save_all(credentials)
        return credential

    def delete(self, credential_id: str) -> bool:
        credentials = self.list_all()
        new_credentials = [c for c in credentials if c.id != credential_id]
        if len(new_credentials) == len(credentials):
            return False
        self._save_all(new_credentials)
        return True

    def mark_rotated(self, credential_id: str, rotated_at: Optional[datetime] = None) -> Credential:
        cred = self.get_by_id(credential_id)
        if not cred:
            raise ValueError(f"Credential with id '{credential_id}' not found")
        rotated_at = rotated_at or datetime.now()
        cred.last_rotated_at = rotated_at
        cred.status = CredentialStatus.ROTATED
        return self.update(cred)

    def bulk_add(self, credentials: list[Credential]) -> list[Credential]:
        existing_ids = {c.id for c in self.list_all()}
        added = []
        for cred in credentials:
            if cred.id in existing_ids:
                continue
            added.append(cred)
            existing_ids.add(cred.id)
        if added:
            all_creds = self.list_all() + added
            self._save_all(all_creds)
        return added
