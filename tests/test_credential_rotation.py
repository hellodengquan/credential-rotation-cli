import json
import os
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from credential_rotation.exporter import export_to_ical
from credential_rotation.importer import generate_csv_template, parse_csv_import
from credential_rotation.models import (
    _DEFAULT_TYPE_CONFIGS,
    Credential,
    CredentialStatus,
    TypeConfigRegistry,
    get_type_config,
)
from credential_rotation.remote import is_remote_path
from credential_rotation.rotation import RotationAction, RotationManager
from credential_rotation.storage import Storage
from credential_rotation.vault import (
    VAULT_BACKENDS,
    EnvFileVaultBackend,
)


@pytest.fixture
def tmp_storage(tmp_path):
    return Storage(tmp_path / "test_creds.json", use_keyring=False)


@pytest.fixture
def manager(tmp_storage):
    return RotationManager(tmp_storage)


def _make_credential(
    cred_id="test-001",
    name="Test Cred",
    cred_type="api_key",
    expires_at=None,
    environment=None,
    service=None,
    **kwargs,
):
    now = datetime.now()
    exp = expires_at or (now + timedelta(days=90))
    return Credential(
        id=cred_id,
        name=name,
        type=cred_type,
        created_at=now,
        expires_at=exp,
        environment=environment,
        service=service,
        **kwargs,
    )


class TestTimezoneDrift:
    def test_expiry_calculation_utc_vs_local(self):
        utc_now = datetime(2026, 6, 16, 23, 0, 0, tzinfo=timezone.utc)
        shanghai_now = datetime(2026, 6, 17, 7, 0, 0, tzinfo=timezone(timedelta(hours=8)))
        datetime(2026, 6, 20, 0, 0, 0, tzinfo=timezone.utc)
        naive_expires = datetime(2026, 6, 20, 0, 0, 0)

        Credential(
            id="tz-test",
            name="TZ Test",
            type="api_key",
            created_at=datetime(2026, 1, 1),
            expires_at=naive_expires,
            warning_days=14,
        )

        days_from_utc = (naive_expires - utc_now.replace(tzinfo=None)).days
        days_from_shanghai = (naive_expires - shanghai_now.replace(tzinfo=None)).days

        assert days_from_utc >= 0
        assert abs(days_from_utc - days_from_shanghai) <= 1

    def test_expiry_near_midnight_boundary(self):
        cred = Credential(
            id="midnight-test",
            name="Midnight",
            type="api_key",
            created_at=datetime(2026, 1, 1),
            expires_at=datetime(2026, 6, 16, 23, 59, 59),
            warning_days=14,
        )
        now_early = datetime(2026, 6, 2, 0, 0, 0)
        now_late = datetime(2026, 6, 2, 23, 59, 59)

        status_early = cred.get_status(now_early)
        status_late = cred.get_status(now_late)
        assert status_early == CredentialStatus.EXPIRING_SOON
        assert status_late == CredentialStatus.EXPIRING_SOON

    def test_multi_timezone_same_timestamp(self):
        expires = datetime(2026, 12, 31, 23, 59, 59)
        cred = Credential(
            id="multi-tz",
            name="Multi TZ",
            type="api_key",
            created_at=datetime(2026, 1, 1),
            expires_at=expires,
        )
        tzs = [
            datetime(2026, 12, 20, 0, 0, 0),
            datetime(2026, 12, 20, 12, 0, 0),
            datetime(2026, 12, 20, 23, 59, 59),
        ]
        for now in tzs:
            status = cred.get_status(now)
            assert status == CredentialStatus.EXPIRING_SOON


class TestLeapYear:
    def test_leap_year_feb29_expiry(self):
        cred = Credential(
            id="leap-test",
            name="Leap Year",
            type="certificate",
            created_at=datetime(2024, 1, 1),
            expires_at=datetime(2028, 2, 29, 23, 59, 59),
        )
        assert cred.expires_at.day == 29
        assert cred.expires_at.month == 2

        now = datetime(2028, 2, 1)
        assert cred.is_expiring_soon(now)
        assert not cred.is_expired(now)

        now = datetime(2028, 3, 1)
        assert cred.is_expired(now)

    def test_leap_year_creation(self):
        cred = Credential(
            id="leap-create",
            name="Leap Create",
            type="token",
            created_at=datetime(2024, 2, 29),
            expires_at=datetime(2024, 3, 29, 23, 59, 59),
        )
        assert cred.created_at.day == 29

    def test_non_leap_year_feb28(self):
        cred = Credential(
            id="non-leap",
            name="Non Leap",
            type="password",
            created_at=datetime(2025, 1, 1),
            expires_at=datetime(2025, 2, 28, 23, 59, 59),
        )
        now = datetime(2025, 2, 28)
        assert not cred.is_expired(now)

        now = datetime(2025, 3, 1)
        assert cred.is_expired(now)


class TestExpiredCredentials:
    def test_expired_status(self):
        cred = _make_credential(expires_at=datetime(2020, 1, 1, 23, 59, 59))
        assert cred.is_expired()
        assert cred.get_status() == CredentialStatus.EXPIRED

    def test_just_expired(self):
        cred = _make_credential(expires_at=datetime.now() - timedelta(seconds=1))
        assert cred.is_expired()

    def test_negative_days_until_expiry(self):
        cred = _make_credential(expires_at=datetime(2020, 1, 1))
        days = cred.days_until_expiry()
        assert days < 0

    def test_expiring_soon_boundary(self):
        now = datetime.now()
        cred = _make_credential(
            expires_at=now + timedelta(days=14),
            warning_days=14,
        )
        assert cred.is_expiring_soon(now)

    def test_rotation_action_for_expired(self):
        cred = _make_credential(expires_at=datetime(2020, 1, 1))
        manager = RotationManager(MagicMock())
        action = manager.get_action_for_credential(cred)
        assert action == RotationAction.ROTATE_NOW


class TestEnvironmentIsolation:
    def test_conflict_detection_isolated_by_environment(self):
        cred1 = _make_credential(
            cred_id="prod-001",
            service="aws",
            environment="prod",
            expires_at=datetime(2026, 7, 1, 23, 59, 59),
        )
        cred2 = _make_credential(
            cred_id="staging-001",
            service="aws",
            environment="staging",
            expires_at=datetime(2026, 7, 1, 23, 59, 59),
        )
        manager = MagicMock()
        rm = RotationManager(manager)
        conflicts = rm.detect_concurrent_rotation_conflicts(
            credentials=[cred1, cred2],
            cross_environment=False,
        )
        assert len(conflicts) == 0

    def test_conflict_detection_cross_environment(self):
        cred1 = _make_credential(
            cred_id="prod-001",
            service="aws",
            environment="prod",
            expires_at=datetime(2026, 7, 1, 23, 59, 59),
        )
        cred2 = _make_credential(
            cred_id="staging-001",
            service="aws",
            environment="staging",
            expires_at=datetime(2026, 7, 1, 23, 59, 59),
        )
        manager = MagicMock()
        rm = RotationManager(manager)
        conflicts = rm.detect_concurrent_rotation_conflicts(
            credentials=[cred1, cred2],
            cross_environment=True,
        )
        assert len(conflicts) > 0

    def test_same_environment_conflict(self):
        cred1 = _make_credential(
            cred_id="prod-001",
            service="aws",
            environment="prod",
            expires_at=datetime(2026, 7, 1, 23, 59, 59),
        )
        cred2 = _make_credential(
            cred_id="prod-002",
            service="aws",
            environment="prod",
            expires_at=datetime(2026, 7, 1, 23, 59, 59),
        )
        manager = MagicMock()
        rm = RotationManager(manager)
        conflicts = rm.detect_concurrent_rotation_conflicts(
            credentials=[cred1, cred2],
            cross_environment=False,
        )
        assert len(conflicts) > 0

    def test_different_services_no_conflict(self):
        cred1 = _make_credential(
            cred_id="aws-001",
            service="aws",
            environment="prod",
            expires_at=datetime(2026, 7, 1, 23, 59, 59),
        )
        cred2 = _make_credential(
            cred_id="gcp-001",
            service="gcp",
            environment="prod",
            expires_at=datetime(2026, 7, 1, 23, 59, 59),
        )
        manager = MagicMock()
        rm = RotationManager(manager)
        conflicts = rm.detect_concurrent_rotation_conflicts(
            credentials=[cred1, cred2],
            cross_environment=False,
        )
        assert len(conflicts) == 0


class TestRemotePathDetection:
    def test_s3_path(self):
        assert is_remote_path("s3://my-bucket/creds.csv")

    def test_sftp_path(self):
        assert is_remote_path("sftp://myhost.com/data/creds.csv")

    def test_local_path(self):
        assert not is_remote_path("/tmp/creds.csv")

    def test_relative_path(self):
        assert not is_remote_path("creds.csv")


class TestCSVImport:
    def test_import_with_environment(self, tmp_path):
        csv_content = "id,name,type,expires_at,service,environment\n"
        csv_content += "test-001,Test Key,api_key,2026-12-31,aws,prod\n"
        csv_path = tmp_path / "test.csv"
        csv_path.write_text(csv_content, encoding="utf-8")

        creds, errors = parse_csv_import(csv_path)
        assert len(creds) == 1
        assert len(errors) == 0
        assert creds[0].environment == "prod"
        assert creds[0].service == "aws"

    def test_import_missing_required_field(self, tmp_path):
        csv_content = "id,name,type\n"
        csv_content += "test-001,Test Key,api_key\n"
        csv_path = tmp_path / "test.csv"
        csv_path.write_text(csv_content, encoding="utf-8")

        creds, errors = parse_csv_import(csv_path)
        assert len(creds) == 0
        assert len(errors) == 1
        assert "expires_at" in errors[0]["error"]

    def test_import_invalid_date(self, tmp_path):
        csv_content = "id,name,type,expires_at\n"
        csv_content += "test-001,Test Key,api_key,not-a-date\n"
        csv_path = tmp_path / "test.csv"
        csv_path.write_text(csv_content, encoding="utf-8")

        creds, errors = parse_csv_import(csv_path)
        assert len(creds) == 0
        assert len(errors) == 1

    def test_template_generation(self, tmp_path):
        output = tmp_path / "template.csv"
        generate_csv_template(output)
        assert output.exists()
        content = output.read_text(encoding="utf-8")
        assert "environment" in content


class TestEnvFileVaultBackend:
    def test_store_and_retrieve(self, tmp_path):
        vault = EnvFileVaultBackend(
            vault_path=tmp_path / "vault.json",
            encryption_key="test-key",
        )
        vault.store("cred-001", {"secret": "abc123"})
        result = vault.retrieve("cred-001")
        assert result is not None
        assert result["secret"] == "abc123"

    def test_delete(self, tmp_path):
        vault = EnvFileVaultBackend(
            vault_path=tmp_path / "vault.json",
            encryption_key="test-key",
        )
        vault.store("cred-001", {"secret": "abc123"})
        assert vault.delete("cred-001")
        assert vault.retrieve("cred-001") is None

    def test_list_ids(self, tmp_path):
        vault = EnvFileVaultBackend(
            vault_path=tmp_path / "vault.json",
            encryption_key="test-key",
        )
        vault.store("cred-001", {"secret": "a"})
        vault.store("cred-002", {"secret": "b"})
        ids = vault.list_ids()
        assert "cred-001" in ids
        assert "cred-002" in ids

    def test_different_keys_cannot_decrypt(self, tmp_path):
        vault_path = tmp_path / "vault.json"
        vault1 = EnvFileVaultBackend(vault_path=vault_path, encryption_key="key1")
        vault1.store("cred-001", {"secret": "abc123"})

        vault2 = EnvFileVaultBackend(vault_path=vault_path, encryption_key="key2")
        result = vault2.retrieve("cred-001")
        assert result is None or result.get("secret") != "abc123"

    def test_env_var_key(self, tmp_path):
        with patch.dict(os.environ, {"CREDROT_VAULT_KEY": "env-key-123"}):
            vault = EnvFileVaultBackend(vault_path=tmp_path / "vault.json")
            vault.store("cred-001", {"secret": "from-env"})
            result = vault.retrieve("cred-001")
            assert result is not None
            assert result["secret"] == "from-env"


class TestTypeConfigRegistry:
    def test_default_configs(self):
        registry = TypeConfigRegistry()
        for key in _DEFAULT_TYPE_CONFIGS:
            cfg = registry.get(key)
            assert cfg is not None
            assert "rotation_period_days" in cfg
            assert "warning_days" in cfg

    def test_register_custom(self):
        registry = TypeConfigRegistry()
        registry.register("custom_type", rotation_period_days=45, warning_days=10)
        cfg = registry.get("custom_type")
        assert cfg["rotation_period_days"] == 45
        assert cfg["warning_days"] == 10

    def test_unregister_custom(self):
        registry = TypeConfigRegistry()
        registry.register("custom_type", rotation_period_days=45, warning_days=10)
        assert registry.unregister("custom_type")
        cfg = registry.get("custom_type")
        assert cfg == registry.get("api_key")

    def test_cannot_unregister_default(self):
        registry = TypeConfigRegistry()
        assert not registry.unregister("api_key")

    def test_save_and_load_custom(self, tmp_path):
        config_path = tmp_path / "type_configs.json"
        with patch("credential_rotation.models.CUSTOM_CONFIG_PATH", config_path):
            registry = TypeConfigRegistry()
            registry.register("my_type", rotation_period_days=120, warning_days=21)
            registry.save_custom()

            assert config_path.exists()
            loaded = json.loads(config_path.read_text(encoding="utf-8"))
            assert "my_type" in loaded

    def test_unknown_type_falls_back(self):
        cfg = get_type_config("totally_unknown_type")
        assert cfg == get_type_config("api_key")


class TestIcalExport:
    def test_ical_with_timezone(self, tmp_path):
        rotation_list = [
            {
                "id": "test-001",
                "name": "Test Key",
                "type": "api_key",
                "status": "expiring_soon",
                "action": "schedule_soon",
                "expires_at": "2026-12-31T23:59:59",
                "days_until_expiry": 15,
                "owner": "devops",
                "service": "aws",
                "environment": "prod",
                "conflict": {"has_conflict": False, "conflicting_ids": [], "details": ""},
            }
        ]
        output = tmp_path / "test.ics"
        export_to_ical(rotation_list, output, timezone_id="Asia/Shanghai")
        content = output.read_text(encoding="utf-8")
        assert "VCALENDAR" in content
        assert "VTIMEZONE" in content
        assert "Asia/Shanghai" in content
        assert "DTSTART;TZID=Asia/Shanghai" in content
        assert "DTEND;TZID=Asia/Shanghai" in content

    def test_ical_utc_no_vtimezone(self, tmp_path):
        rotation_list = [
            {
                "id": "test-001",
                "name": "Test Key",
                "type": "api_key",
                "status": "expired",
                "action": "rotate_now",
                "expires_at": "2026-06-01T23:59:59",
                "days_until_expiry": -15,
                "owner": "",
                "service": "",
                "environment": "",
                "conflict": {"has_conflict": False, "conflicting_ids": [], "details": ""},
            }
        ]
        output = tmp_path / "test_utc.ics"
        export_to_ical(rotation_list, output, timezone_id="UTC")
        content = output.read_text(encoding="utf-8")
        assert "VCALENDAR" in content
        assert "VTIMEZONE" not in content
        assert "DTSTART:" in content

    def test_ical_with_conflict(self, tmp_path):
        rotation_list = [
            {
                "id": "test-001",
                "name": "Test Key",
                "type": "api_key",
                "status": "expiring_soon",
                "action": "rotate_now",
                "expires_at": "2026-07-01T23:59:59",
                "days_until_expiry": 5,
                "owner": "",
                "service": "aws",
                "environment": "prod",
                "conflict": {
                    "has_conflict": True,
                    "conflicting_ids": ["test-002"],
                    "details": "同服务 aws 下并发轮换冲突",
                },
            }
        ]
        output = tmp_path / "test_conflict.ics"
        export_to_ical(rotation_list, output)
        content = output.read_text(encoding="utf-8")
        assert "test-002" in content
        assert "VALARM" in content


class TestStorageKeyringFallback:
    def test_keyring_fallback_to_plain(self, tmp_path):
        storage = Storage(tmp_path / "test.json", use_keyring=False)
        cred = _make_credential()
        storage.add(cred)
        loaded = storage.get_by_id(cred.id)
        assert loaded is not None
        assert loaded.secret_value is None

    def test_keyring_unavailable_graceful(self, tmp_path):
        storage = Storage(tmp_path / "test.json", use_keyring=True)
        cred = _make_credential(secret_value="super-secret")
        with patch("credential_rotation.storage._encrypt_field", return_value="super-secret"):
            storage.add(cred)
        loaded = storage.get_by_id(cred.id)
        assert loaded is not None


class TestVaultBackendRegistry:
    def test_available_backends(self):
        assert "file" in VAULT_BACKENDS
        assert "keyring" in VAULT_BACKENDS
        assert "envfile" in VAULT_BACKENDS
        assert "aws" in VAULT_BACKENDS
        assert "gcp" in VAULT_BACKENDS

    def test_unknown_backend_raises(self):
        from credential_rotation.vault import get_vault_backend

        with pytest.raises(ValueError, match="Unknown vault backend"):
            get_vault_backend("nonexistent")
