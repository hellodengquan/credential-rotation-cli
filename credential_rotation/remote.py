import tempfile
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional


class RemoteFetcher(ABC):
    @abstractmethod
    def fetch(self, remote_path: str) -> Path: ...

    @abstractmethod
    def scheme(self) -> str: ...


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

    def scheme(self) -> str:
        return "s3"

    def fetch(self, remote_path: str) -> Path:
        import boto3

        if not remote_path.startswith("s3://"):
            raise ValueError(f"Invalid S3 path: {remote_path}. Must start with s3://")

        path_no_scheme = remote_path[5:]
        slash_idx = path_no_scheme.find("/")
        if slash_idx == -1:
            raise ValueError(f"Invalid S3 path: {remote_path}. Must be s3://bucket/key")
        bucket = path_no_scheme[:slash_idx]
        key = path_no_scheme[slash_idx + 1 :]

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
        s3 = session.client("s3", **client_kwargs)

        filename = key.rsplit("/", 1)[-1] or "download.csv"
        local_path = Path(tempfile.mkdtemp()) / filename
        s3.download_file(bucket, key, str(local_path))
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

    def scheme(self) -> str:
        return "sftp"

    def fetch(self, remote_path: str) -> Path:
        import paramiko

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
