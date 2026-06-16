import tempfile
from abc import ABC, abstractmethod
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

DEFAULT_CLOCK_DRIFT_TOLERANCE = timedelta(minutes=5)


@dataclass
class RemoteFetchResult:
    local_path: Path
    last_modified: Optional[datetime]
    was_updated: bool
    etag: Optional[str] = None
    clock_drift_detected: bool = False
    clock_drift_delta: Optional[timedelta] = None


@dataclass
class ClockDriftConfig:
    tolerance: timedelta = field(default_factory=lambda: DEFAULT_CLOCK_DRIFT_TOLERANCE)
    force_fetch_on_drift: bool = True
    max_drift: timedelta = field(default_factory=lambda: timedelta(hours=1))
    last_remote_time: Optional[datetime] = None
    last_local_time: Optional[datetime] = None

    def check_drift(
        self, remote_time: Optional[datetime], local_time: Optional[datetime] = None
    ) -> tuple[bool, Optional[timedelta]]:
        if remote_time is None:
            return False, None
        local_now = local_time or datetime.now(timezone.utc)
        if remote_time.tzinfo is None:
            remote_time = remote_time.replace(tzinfo=timezone.utc)
        if local_now.tzinfo is None:
            local_now = local_now.replace(tzinfo=timezone.utc)
        self.last_remote_time = remote_time
        self.last_local_time = local_now
        delta = remote_time - local_now
        abs_delta = abs(delta)
        if abs_delta > self.tolerance:
            return True, delta
        return False, None

    def is_drift_acceptable(self, delta: Optional[timedelta]) -> bool:
        if delta is None:
            return True
        return abs(delta) <= self.max_drift


class RemoteFetcher(ABC):
    @abstractmethod
    def fetch(self, remote_path: str) -> Path: ...

    @abstractmethod
    def scheme(self) -> str: ...

    @abstractmethod
    def get_last_modified(self, remote_path: str) -> Optional[datetime]: ...

    def fetch_if_newer(
        self,
        remote_path: str,
        since: Optional[datetime] = None,
        local_etag: Optional[str] = None,
        clock_drift_config: Optional[ClockDriftConfig] = None,
    ) -> Optional[RemoteFetchResult]:
        last_mod = self.get_last_modified(remote_path)
        clock_drift_detected = False
        clock_drift_delta: Optional[timedelta] = None

        if clock_drift_config and last_mod:
            clock_drift_detected, clock_drift_delta = clock_drift_config.check_drift(last_mod)
            if clock_drift_detected and not clock_drift_config.is_drift_acceptable(
                clock_drift_delta
            ):
                return RemoteFetchResult(
                    local_path=Path(""),
                    last_modified=last_mod,
                    was_updated=False,
                    clock_drift_detected=True,
                    clock_drift_delta=clock_drift_delta,
                )
            if clock_drift_detected and clock_drift_config.force_fetch_on_drift:
                local_path = self.fetch(remote_path)
                etag = getattr(self, "_last_etag", None)
                return RemoteFetchResult(
                    local_path=local_path,
                    last_modified=last_mod,
                    was_updated=True,
                    etag=etag,
                    clock_drift_detected=True,
                    clock_drift_delta=clock_drift_delta,
                )

        if since and last_mod and last_mod <= since:
            return RemoteFetchResult(
                local_path=Path(""),
                last_modified=last_mod,
                was_updated=False,
            )
        local_path = self.fetch(remote_path)
        etag = getattr(self, "_last_etag", None)
        return RemoteFetchResult(
            local_path=local_path,
            last_modified=last_mod,
            was_updated=True,
            etag=etag,
            clock_drift_detected=clock_drift_detected,
            clock_drift_delta=clock_drift_delta,
        )


class S3Fetcher(RemoteFetcher):
    def __init__(
        self,
        endpoint_url: Optional[str] = None,
        region: Optional[str] = None,
        aws_access_key_id: Optional[str] = None,
        aws_secret_access_key: Optional[str] = None,
    ):
        self.endpoint_url = endpoint_url
        self.region = region
        self.aws_access_key_id = aws_access_key_id
        self.aws_secret_access_key = aws_secret_access_key
        self._client = None
        self._last_etag: Optional[str] = None
        self._last_modified: Optional[datetime] = None

    def scheme(self) -> str:
        return "s3"

    def _get_client(self):
        import boto3

        if self._client is None:
            session_kwargs = {}
            if self.aws_access_key_id:
                session_kwargs["aws_access_key_id"] = self.aws_access_key_id
            if self.aws_secret_access_key:
                session_kwargs["aws_secret_access_key"] = self.aws_secret_access_key
            if self.region:
                session_kwargs["region_name"] = self.region
            session = boto3.Session(**session_kwargs)
            client_kwargs = {}
            if self.endpoint_url:
                client_kwargs["endpoint_url"] = self.endpoint_url
            self._client = session.client("s3", **client_kwargs)
        return self._client

    @staticmethod
    def _parse_s3_path(remote_path: str) -> tuple[str, str]:
        if not remote_path.startswith("s3://"):
            raise ValueError(f"Invalid S3 path: {remote_path}. Must start with s3://")
        path_no_scheme = remote_path[5:]
        slash_idx = path_no_scheme.find("/")
        if slash_idx == -1:
            raise ValueError(f"Invalid S3 path: {remote_path}. Must be s3://bucket/key")
        bucket = path_no_scheme[:slash_idx]
        key = path_no_scheme[slash_idx + 1 :]
        return bucket, key

    def get_last_modified(self, remote_path: str) -> Optional[datetime]:
        bucket, key = self._parse_s3_path(remote_path)
        s3 = self._get_client()
        try:
            head = s3.head_object(Bucket=bucket, Key=key)
            lm = head.get("LastModified")
            if lm:
                if lm.tzinfo is None:
                    lm = lm.replace(tzinfo=timezone.utc)
                self._last_modified = lm
                self._last_etag = head.get("ETag", "").strip('"')
                return lm  # type: ignore[no-any-return]
        except Exception:
            pass
        return None

    def fetch(self, remote_path: str) -> Path:
        bucket, key = self._parse_s3_path(remote_path)
        s3 = self._get_client()
        filename = key.rsplit("/", 1)[-1] or "download.csv"
        local_path = Path(tempfile.mkdtemp()) / filename
        s3.download_file(bucket, key, str(local_path))
        self.get_last_modified(remote_path)
        return local_path


class SFTPFetcher(RemoteFetcher):
    def __init__(
        self,
        host: str,
        port: int = 22,
        username: Optional[str] = None,
        password: Optional[str] = None,
        key_filename: Optional[str] = None,
    ):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.key_filename = key_filename
        self._client = None
        self._sftp = None
        self._last_modified: Optional[datetime] = None

    def scheme(self) -> str:
        return "sftp"

    def _connect(self):
        import paramiko

        if self._client is None:
            self._client = paramiko.SSHClient()
            self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # type: ignore[attr-defined]
            connect_kwargs: dict = {
                "hostname": self.host,
                "port": self.port,
            }
            if self.username:
                connect_kwargs["username"] = self.username
            if self.password:
                connect_kwargs["password"] = self.password
            if self.key_filename:
                connect_kwargs["key_filename"] = self.key_filename
            self._client.connect(**connect_kwargs)  # type: ignore[attr-defined]
            self._sftp = self._client.open_sftp()  # type: ignore[attr-defined]
        return self._sftp

    def close(self):
        if self._sftp:
            self._sftp.close()
            self._sftp = None
        if self._client:
            self._client.close()
            self._client = None

    def get_last_modified(self, remote_path: str) -> Optional[datetime]:
        try:
            sftp = self._connect()
            stat = sftp.stat(remote_path)
            mtime = getattr(stat, "st_mtime", None)
            if mtime:
                dt = datetime.fromtimestamp(mtime, tz=timezone.utc)
                self._last_modified = dt
                return dt
        except Exception:
            pass
        return None

    def fetch(self, remote_path: str) -> Path:
        import paramiko

        if self._client is not None:
            sftp = self._connect()
            filename = remote_path.rsplit("/", 1)[-1] or "download.csv"
            local_path = Path(tempfile.mkdtemp()) / filename
            sftp.get(remote_path, str(local_path))
            self.get_last_modified(remote_path)
            return local_path

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        connect_kwargs: dict = {
            "hostname": self.host,
            "port": self.port,
        }
        if self.username:
            connect_kwargs["username"] = self.username
        if self.password:
            connect_kwargs["password"] = self.password
        if self.key_filename:
            connect_kwargs["key_filename"] = self.key_filename

        try:
            client.connect(**connect_kwargs)
            sftp = client.open_sftp()
            filename = remote_path.rsplit("/", 1)[-1] or "download.csv"
            local_path = Path(tempfile.mkdtemp()) / filename
            sftp.get(remote_path, str(local_path))
            stat = sftp.stat(remote_path)
            mtime = getattr(stat, "st_mtime", None)
            if mtime:
                self._last_modified = datetime.fromtimestamp(mtime, tz=timezone.utc)
            return local_path
        finally:
            client.close()


FETCHER_REGISTRY: dict[str, type[RemoteFetcher]] = {
    "s3": S3Fetcher,
    "sftp": SFTPFetcher,
}


def is_remote_path(path: str) -> bool:
    return any(path.startswith(f"{scheme}://") for scheme in FETCHER_REGISTRY)


def fetch_remote(remote_path: str, **kwargs) -> Path:
    scheme = remote_path.split("://", 1)[0].lower()
    fetcher_cls = FETCHER_REGISTRY.get(scheme)
    if fetcher_cls is None:
        raise ValueError(
            f"Unsupported remote scheme '{scheme}'. Supported: {', '.join(FETCHER_REGISTRY.keys())}"
        )
    fetcher = fetcher_cls(**kwargs)
    return fetcher.fetch(remote_path)


def fetch_remote_incremental(
    remote_path: str,
    since: Optional[datetime] = None,
    local_etag: Optional[str] = None,
    clock_drift_config: Optional[ClockDriftConfig] = None,
    **kwargs,
) -> Optional[RemoteFetchResult]:
    scheme = remote_path.split("://", 1)[0].lower()
    fetcher_cls = FETCHER_REGISTRY.get(scheme)
    if fetcher_cls is None:
        raise ValueError(
            f"Unsupported remote scheme '{scheme}'. Supported: {', '.join(FETCHER_REGISTRY.keys())}"
        )
    fetcher = fetcher_cls(**kwargs)
    try:
        return fetcher.fetch_if_newer(
            remote_path,
            since=since,
            local_etag=local_etag,
            clock_drift_config=clock_drift_config,
        )
    finally:
        if hasattr(fetcher, "close"):
            with suppress(Exception):
                fetcher.close()
