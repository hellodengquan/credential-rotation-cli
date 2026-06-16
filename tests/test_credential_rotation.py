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


class TestUtcMidnightBoundary:
    def test_expires_exactly_at_utc_midnight(self):
        cred = _make_credential(
            expires_at=datetime(2026, 6, 17, 0, 0, 0),
            warning_days=7,
        )
        now_before = datetime(2026, 6, 16, 23, 59, 59)
        now_after = datetime(2026, 6, 17, 0, 0, 1)
        assert not cred.is_expired(now_before)
        assert cred.is_expired(now_after)

    def test_expires_at_midnight_utc_vs_local(self):
        cred = _make_credential(
            expires_at=datetime(2026, 6, 17, 0, 0, 0),
            warning_days=7,
        )
        utc_now = datetime(2026, 6, 16, 23, 0, 0, tzinfo=timezone.utc)
        local_now = datetime(2026, 6, 17, 7, 0, 0)
        assert not cred.is_expired(utc_now.replace(tzinfo=None))
        assert cred.is_expired(local_now)

    def test_warning_window_at_midnight_crossing(self):
        cred = _make_credential(
            expires_at=datetime(2026, 6, 17, 0, 0, 0),
            warning_days=7,
        )
        now_before_warning = datetime(2026, 6, 9, 0, 0, 0)
        now_after_warning = datetime(2026, 6, 10, 0, 0, 0)
        assert not cred.is_expiring_soon(now_before_warning)
        assert cred.is_expiring_soon(now_after_warning)

    def test_rotation_action_at_midnight_switch(self):
        cred = _make_credential(
            expires_at=datetime(2026, 6, 25, 0, 0, 0),
            warning_days=14,
        )
        manager = MagicMock()
        rm = RotationManager(manager)
        action_before = rm.get_action_for_credential(cred, now=datetime(2026, 6, 16, 23, 59, 59))
        action_after = rm.get_action_for_credential(cred, now=datetime(2026, 6, 17, 0, 0, 1))
        assert action_before == RotationAction.SCHEDULE_SOON
        assert action_after == RotationAction.ROTATE_NOW

    def test_year_boundary_midnight(self):
        cred = _make_credential(
            expires_at=datetime(2027, 1, 1, 0, 0, 0),
            warning_days=14,
        )
        now_before = datetime(2026, 12, 31, 23, 59, 59)
        now_after = datetime(2027, 1, 1, 0, 0, 0)
        assert not cred.is_expired(now_before)
        assert cred.is_expired(now_after)


class TestNamespaceIsolation:
    def test_validate_namespace_valid(self):
        from credential_rotation.namespace import validate_namespace

        assert validate_namespace("prod")
        assert validate_namespace("staging")
        assert validate_namespace("ns-123")
        assert validate_namespace("a.b_c")

    def test_validate_namespace_invalid(self):
        from credential_rotation.namespace import validate_namespace

        assert not validate_namespace("")
        assert not validate_namespace("ns::bad")
        assert not validate_namespace("../evil")
        assert not validate_namespace("a" * 64)

    def test_split_namespace_qualified(self):
        from credential_rotation.namespace import split_namespace

        info = split_namespace("prod::cred-001")
        assert info.namespace == "prod"
        assert info.resource_id == "cred-001"

    def test_split_namespace_default(self):
        from credential_rotation.namespace import split_namespace

        info = split_namespace("cred-001")
        assert info.namespace == "default"
        assert info.resource_id == "cred-001"

    def test_join_namespace(self):
        from credential_rotation.namespace import join_namespace

        qid = join_namespace("prod", "cred-001")
        assert qid == "prod::cred-001"

    def test_join_namespace_invalid_raises(self):
        from credential_rotation.namespace import NamespaceSecurityError, join_namespace

        with pytest.raises(NamespaceSecurityError):
            join_namespace("bad::ns", "cred-001")

    def test_isolator_allow_list(self):
        from credential_rotation.namespace import NamespaceIsolator, NamespaceSecurityError

        isolator = NamespaceIsolator(allowed_namespaces=["prod", "staging"])
        isolator.assert_isolated("prod::cred-001")
        isolator.assert_isolated("staging::cred-002")
        with pytest.raises(NamespaceSecurityError):
            isolator.assert_isolated("evil::cred-003")

    def test_isolator_hijack_detection(self):
        from contextlib import suppress

        from credential_rotation.namespace import NamespaceIsolator, NamespaceSecurityError

        isolator = NamespaceIsolator(allowed_namespaces=["prod"])
        assert not isolator.hijack_detected
        with suppress(NamespaceSecurityError):
            isolator.assert_isolated("hacked::cred-001", "read")
        assert isolator.hijack_detected
        assert "hacked" in isolator.hijacked_namespaces

    def test_vault_namespace_adapter(self):
        from credential_rotation.namespace import VaultNamespaceAdapter
        from credential_rotation.vault import FileVaultBackend

        vault = FileVaultBackend()
        prod_vault = VaultNamespaceAdapter(vault, namespace="prod")
        staging_vault = VaultNamespaceAdapter(vault, namespace="staging")
        prod_vault.store("cred-001", {"value": "prod-secret"})
        staging_vault.store("cred-001", {"value": "staging-secret"})
        prod_result = prod_vault.retrieve("cred-001")
        staging_result = staging_vault.retrieve("cred-001")
        assert prod_result is not None
        assert prod_result["value"] == "prod-secret"
        assert staging_result is not None
        assert staging_result["value"] == "staging-secret"
        assert len(vault.list_ids()) == 2
        assert len(prod_vault.list_ids()) == 1
        assert "cred-001" in prod_vault.list_ids()

    def test_vault_namespace_cross_access_denied(self):
        from credential_rotation.namespace import NamespaceSecurityError, VaultNamespaceAdapter
        from credential_rotation.vault import FileVaultBackend

        vault = FileVaultBackend()
        prod_vault = VaultNamespaceAdapter(vault, namespace="prod")
        vault.store("staging::cred-001", {"value": "evil"})
        with pytest.raises(NamespaceSecurityError):
            prod_vault.retrieve("staging::cred-001")


class TestTypeConfigDrain:
    def test_disable_custom_drain_mode(self):
        registry = TypeConfigRegistry()
        registry.register("custom_type", rotation_period_days=45, warning_days=10)
        draining_types = registry.disable_custom(drain=True)
        assert "custom_type" in draining_types
        assert registry.drain_mode
        cfg = registry.get("custom_type")
        assert cfg["rotation_period_days"] == 45
        assert registry.is_draining_type("custom_type")

    def test_disable_custom_hard(self):
        registry = TypeConfigRegistry()
        registry.register("custom_type", rotation_period_days=45, warning_days=10)
        removed = registry.disable_custom(drain=False)
        assert "custom_type" in removed
        assert not registry.drain_mode
        cfg = registry.get("custom_type")
        default_cfg = registry.get("api_key")
        assert cfg == default_cfg

    def test_reset_drain_mode(self):
        registry = TypeConfigRegistry()
        registry.register("custom_type", rotation_period_days=45, warning_days=10)
        registry.disable_custom(drain=True)
        assert registry.drain_mode
        registry.reset_drain_mode()
        assert not registry.drain_mode
        assert registry.custom_enabled

    def test_cannot_register_in_drain_mode(self):
        registry = TypeConfigRegistry()
        registry.register("custom_type", rotation_period_days=45, warning_days=10)
        registry.disable_custom(drain=True)
        with pytest.raises(RuntimeError):
            registry.register("another", rotation_period_days=30, warning_days=7)

    def test_list_draining_types(self):
        registry = TypeConfigRegistry()
        registry.register("custom_a", rotation_period_days=30, warning_days=7)
        registry.register("custom_b", rotation_period_days=60, warning_days=14)
        registry.disable_custom(drain=True)
        draining = registry.list_draining()
        assert "custom_a" in draining
        assert "custom_b" in draining
        assert len(draining) == 2


class TestRruleCrossYear:
    def test_rrule_yearly(self):
        from credential_rotation.exporter import generate_rrule_from_rotation_days

        rrule = generate_rrule_from_rotation_days(365)
        assert "FREQ=YEARLY" in rrule
        assert "INTERVAL=1" in rrule

    def test_rrule_monthly(self):
        from credential_rotation.exporter import generate_rrule_from_rotation_days

        rrule = generate_rrule_from_rotation_days(30)
        assert "FREQ=MONTHLY" in rrule

    def test_rrule_daily(self):
        from credential_rotation.exporter import generate_rrule_from_rotation_days

        rrule = generate_rrule_from_rotation_days(45)
        assert "FREQ=DAILY" in rrule
        assert "INTERVAL=45" in rrule

    def test_cross_year_recurrence_sample(self):
        from credential_rotation.exporter import generate_cross_year_recurrence_sample

        start = datetime(2026, 1, 15, 10, 0, 0)
        sample = generate_cross_year_recurrence_sample(start, rotation_days=90, years=3)
        assert sample["rotation_days"] == 90
        assert sample["total_events"] > 0
        assert len(sample["years_covered"]) >= 3
        assert 2026 in sample["years_covered"]
        assert "first_5_dates" in sample
        assert "last_5_dates" in sample

    def test_ical_with_rrule(self, tmp_path):
        from credential_rotation.exporter import export_to_ical

        rotation_list = [
            {
                "id": "test-rrule",
                "name": "RRule Test",
                "type": "certificate",
                "status": "active",
                "action": "monitor",
                "expires_at": "2026-12-31T23:59:59",
                "days_until_expiry": 200,
                "rotation_period_days": 365,
                "owner": "",
                "service": "",
                "environment": "",
                "conflict": {"has_conflict": False, "conflicting_ids": [], "details": ""},
            }
        ]
        output = tmp_path / "test_rrule.ics"
        export_to_ical(rotation_list, output, include_rrule=True, rrule_until_years=3)
        content = output.read_text(encoding="utf-8")
        assert "RRULE:" in content
        assert "FREQ=YEARLY" in content
        assert "INTERVAL=1" in content
        assert "UNTIL=" in content


class TestRemoteIncremental:
    def test_remote_fetch_result_dataclass(self):
        from pathlib import Path

        from credential_rotation.remote import RemoteFetchResult

        result = RemoteFetchResult(
            local_path=Path("/tmp/test.csv"),
            last_modified=datetime(2026, 1, 1),
            was_updated=True,
            etag="abc123",
        )
        assert result.was_updated
        assert result.etag == "abc123"

    def test_s3_fetcher_scheme(self):
        from credential_rotation.remote import S3Fetcher

        fetcher = S3Fetcher.__new__(S3Fetcher)
        assert fetcher.scheme() == "s3"

    def test_sftp_fetcher_scheme(self):
        from credential_rotation.remote import SFTPFetcher

        fetcher = SFTPFetcher.__new__(SFTPFetcher)
        assert fetcher.scheme() == "sftp"


class TestIdentityDetection:
    def test_identity_type_enum(self):
        from credential_rotation.vault import IdentityType

        assert IdentityType.ROOT == "root"
        assert IdentityType.SERVICE_ACCOUNT == "service_account"
        assert IdentityType.REGULAR_USER == "regular_user"
        assert IdentityType.UNKNOWN == "unknown"

    def test_detect_identity_regular_user(self):
        from credential_rotation.vault import IdentityType, detect_identity

        identity = detect_identity()
        assert identity in (IdentityType.ROOT, IdentityType.REGULAR_USER, IdentityType.UNKNOWN)

    def test_get_vault_fallback_path(self):
        from credential_rotation.vault import IdentityType, get_vault_fallback_path

        path_regular = get_vault_fallback_path(IdentityType.REGULAR_USER)
        assert ".credential_rotation" in str(path_regular)

        path_root = get_vault_fallback_path(IdentityType.ROOT)
        assert "/var/lib/" in str(path_root)

    def test_env_file_vault_identity_param(self, tmp_path):
        from credential_rotation.vault import EnvFileVaultBackend, IdentityType

        vault = EnvFileVaultBackend(
            vault_path=tmp_path / "vault.json",
            encryption_key="test-key",
            identity=IdentityType.ROOT,
        )
        vault.store("cred-001", {"secret": "root-secret"})
        result = vault.retrieve("cred-001")
        assert result is not None
        assert result["secret"] == "root-secret"


class TestRotationTemplate:
    def test_rotation_template_dataclass(self):
        from credential_rotation.vault import RotationTemplate

        template = RotationTemplate(
            credential_id="cred-001",
            rotation_period_days=90,
            enabled=True,
            backend="aws",
        )
        assert template.credential_id == "cred-001"
        assert template.rotation_period_days == 90
        assert template.enabled
        assert template.backend == "aws"

    def test_vault_supports_rotation_file_false(self):
        from credential_rotation.vault import FileVaultBackend

        vault = FileVaultBackend()
        assert not vault.supports_rotation()

    def test_create_rotation_template_not_implemented(self):
        from credential_rotation.vault import FileVaultBackend

        vault = FileVaultBackend()
        with pytest.raises(NotImplementedError):
            vault.create_rotation_template("test", 90)

    def test_disable_rotation_not_implemented(self):
        from credential_rotation.vault import FileVaultBackend

        vault = FileVaultBackend()
        with pytest.raises(NotImplementedError):
            vault.disable_rotation("test")

    def test_rotate_secret_not_implemented(self):
        from credential_rotation.vault import FileVaultBackend

        vault = FileVaultBackend()
        with pytest.raises(NotImplementedError):
            vault.rotate_secret("test")

    def test_describe_rotation_not_implemented(self):
        from credential_rotation.vault import FileVaultBackend

        vault = FileVaultBackend()
        with pytest.raises(NotImplementedError):
            vault.describe_rotation("test")
