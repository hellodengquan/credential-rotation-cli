import json
import os
from pathlib import Path
from typing import List, Optional
from datetime import datetime

from .models import Credential, CredentialStatus


DEFAULT_STORAGE_PATH = Path.home() / ".credential_rotation" / "credentials.json"


class Storage:
    def __init__(self, storage_path: Optional[Path] = None):
        self.storage_path = storage_path or DEFAULT_STORAGE_PATH
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)

    def _load_all(self) -> List[dict]:
        if not self.storage_path.exists():
            return []
        with open(self.storage_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("credentials", [])

    def _save_all(self, credentials: List[Credential]):
        data = {
            "version": "1.0",
            "updated_at": datetime.now().isoformat(),
            "credentials": [c.to_dict() for c in credentials]
        }
        with open(self.storage_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def list_all(self) -> List[Credential]:
        raw = self._load_all()
        return [Credential.from_dict(item) for item in raw]

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
