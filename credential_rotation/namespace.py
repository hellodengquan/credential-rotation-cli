import hashlib
import json
import os
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

NAMESPACE_SEPARATOR = "::"
NAMESPACE_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,62}$")
MAX_NAMESPACE_LENGTH = 63
KEY_ROTATION_LOG_ENV = "CREDROT_KEY_ROTATION_LOG"


@dataclass
class NamespaceInfo:
    namespace: str
    resource_id: str
    full_id: str


class NamespaceSecurityError(RuntimeError):
    pass


def validate_namespace(namespace: str) -> bool:
    if not namespace or len(namespace) > MAX_NAMESPACE_LENGTH:
        return False
    return bool(NAMESPACE_PATTERN.match(namespace))


def split_namespace(qualified_id: str) -> NamespaceInfo:
    if NAMESPACE_SEPARATOR in qualified_id:
        parts = qualified_id.split(NAMESPACE_SEPARATOR, 1)
        namespace = parts[0]
        resource_id = parts[1]
    else:
        namespace = "default"
        resource_id = qualified_id
    return NamespaceInfo(
        namespace=namespace,
        resource_id=resource_id,
        full_id=qualified_id if NAMESPACE_SEPARATOR in qualified_id else f"default::{qualified_id}",
    )


def join_namespace(namespace: str, resource_id: str) -> str:
    if not validate_namespace(namespace):
        raise NamespaceSecurityError(f"Invalid namespace: {namespace}")
    if NAMESPACE_SEPARATOR in resource_id:
        raise NamespaceSecurityError(
            f"Resource ID cannot contain namespace separator: {resource_id}"
        )
    return f"{namespace}{NAMESPACE_SEPARATOR}{resource_id}"


def is_same_namespace(id1: str, id2: str) -> bool:
    ns1 = split_namespace(id1).namespace
    ns2 = split_namespace(id2).namespace
    return ns1 == ns2


def namespace_hash(namespace: str) -> str:
    return hashlib.sha256(namespace.encode("utf-8")).hexdigest()[:16]


class NamespaceIsolator:
    def __init__(self, allowed_namespaces: Optional[list[str]] = None):
        self._allowed: set[str] = set(allowed_namespaces) if allowed_namespaces else set()
        self._hijack_detected: set[str] = set()

    def allow_namespace(self, namespace: str) -> None:
        if not validate_namespace(namespace):
            raise NamespaceSecurityError(f"Invalid namespace: {namespace}")
        self._allowed.add(namespace)

    def is_allowed(self, namespace: str) -> bool:
        if not self._allowed:
            return True
        return namespace in self._allowed

    def assert_isolated(self, credential_id: str, operation: str = "access") -> None:
        info = split_namespace(credential_id)
        if not validate_namespace(info.namespace):
            raise NamespaceSecurityError(
                f"Hijack detected: invalid namespace '{info.namespace}' in '{credential_id}'"
            )
        if self._allowed and info.namespace not in self._allowed:
            self._hijack_detected.add(info.namespace)
            raise NamespaceSecurityError(
                f"Namespace '{info.namespace}' not allowed for {operation}. "
                f"Allowed: {sorted(self._allowed)}"
            )

    def filter_by_namespace(
        self,
        credentials: list,
        namespace: Optional[str] = None,
    ) -> list:
        if namespace is None:
            if self._allowed:
                return [c for c in credentials if split_namespace(c.id).namespace in self._allowed]
            return list(credentials)
        if not validate_namespace(namespace):
            raise NamespaceSecurityError(f"Invalid namespace: {namespace}")
        return [c for c in credentials if split_namespace(c.id).namespace == namespace]

    @property
    def hijack_detected(self) -> bool:
        return len(self._hijack_detected) > 0

    @property
    def hijacked_namespaces(self) -> list[str]:
        return sorted(self._hijack_detected)

    def clear_hijack_record(self) -> None:
        self._hijack_detected.clear()


class VaultNamespaceAdapter:
    def __init__(self, vault_backend, namespace: str = "default"):
        if not validate_namespace(namespace):
            raise NamespaceSecurityError(f"Invalid namespace: {namespace}")
        self._vault = vault_backend
        self._namespace = namespace

    def _qualify(self, credential_id: str) -> str:
        if NAMESPACE_SEPARATOR in credential_id:
            info = split_namespace(credential_id)
            if info.namespace != self._namespace:
                raise NamespaceSecurityError(
                    f"Cross-namespace access denied: {credential_id} not in {self._namespace}"
                )
            return credential_id
        return join_namespace(self._namespace, credential_id)

    def _strip(self, qualified_id: str) -> str:
        return split_namespace(qualified_id).resource_id

    def store(self, credential_id: str, secret_data: dict[str, str]) -> None:
        qid = self._qualify(credential_id)
        self._vault.store(qid, secret_data)

    def retrieve(self, credential_id: str) -> Optional[dict[str, str]]:
        qid = self._qualify(credential_id)
        return self._vault.retrieve(qid)  # type: ignore[no-any-return]

    def delete(self, credential_id: str) -> bool:
        qid = self._qualify(credential_id)
        return self._vault.delete(qid)  # type: ignore[no-any-return]

    def list_ids(self) -> list[str]:
        all_ids = self._vault.list_ids()
        result = []
        for qid in all_ids:
            info = split_namespace(qid)
            if info.namespace == self._namespace:
                result.append(info.resource_id)
        return result


@dataclass
class KeyRotationRecord:
    namespace: str
    old_key_hash: str
    new_key_hash: str
    rotated_at: str
    rotated_by: str
    affected_credentials: int
    reason: str


class NamespaceKeyManager:
    def __init__(
        self,
        vault_backend,
        key_store_path: Optional[str] = None,
    ):
        self._vault = vault_backend
        self._key_store_path = key_store_path or os.environ.get(
            KEY_ROTATION_LOG_ENV,
            str(os.path.expanduser("~/.credential_rotation/key_rotation_log.json")),
        )
        self._rotation_log: list[KeyRotationRecord] = []
        self._load_rotation_log()

    def _load_rotation_log(self) -> None:
        path = self._key_store_path
        if path and os.path.exists(path):
            try:
                with open(path, encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, list):
                    for entry in data:
                        self._rotation_log.append(KeyRotationRecord(**entry))
            except Exception:
                pass

    def _save_rotation_log(self) -> None:
        if not self._key_store_path:
            return
        os.makedirs(os.path.dirname(self._key_store_path), exist_ok=True)
        with open(self._key_store_path, "w", encoding="utf-8") as f:
            json.dump(
                [vars(r) for r in self._rotation_log],
                f,
                indent=2,
                ensure_ascii=False,
            )

    @staticmethod
    def _hash_key(key: str) -> str:
        return hashlib.sha256(key.encode("utf-8")).hexdigest()[:32]

    def rotate_namespace_key(
        self,
        namespace: str,
        old_key: str,
        reason: str = "key_compromised",
    ) -> KeyRotationRecord:
        if not validate_namespace(namespace):
            raise NamespaceSecurityError(f"Invalid namespace: {namespace}")
        adapter = VaultNamespaceAdapter(self._vault, namespace=namespace)
        affected_ids = adapter.list_ids()
        new_key = secrets.token_urlsafe(48)
        old_hash = self._hash_key(old_key)
        new_hash = self._hash_key(new_key)
        record = KeyRotationRecord(
            namespace=namespace,
            old_key_hash=old_hash,
            new_key_hash=new_hash,
            rotated_at=datetime.now(timezone.utc).isoformat(),
            rotated_by=os.environ.get("USER", "unknown"),
            affected_credentials=len(affected_ids),
            reason=reason,
        )
        self._rotation_log.append(record)
        self._save_rotation_log()
        return record

    def get_rotation_history(self, namespace: Optional[str] = None) -> list[KeyRotationRecord]:
        if namespace is None:
            return list(self._rotation_log)
        return [r for r in self._rotation_log if r.namespace == namespace]

    def check_key_compromised(self, key_hash: str) -> list[KeyRotationRecord]:
        return [r for r in self._rotation_log if r.old_key_hash == key_hash]
