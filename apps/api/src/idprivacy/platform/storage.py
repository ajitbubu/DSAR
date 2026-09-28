"""Evidence object storage behind a small BlobStore interface (ADR-0007).

S3-compatible in every environment (SeaweedFS locally). Objects are private, keyed
opaquely by tenant/request/uuid, and only ever read back through the API.
"""

import threading
from collections.abc import Iterator
from typing import Protocol

import boto3
from botocore.config import Config


class BlobStore(Protocol):
    def put(self, key: str, data: bytes, content_type: str) -> None: ...

    def stream(self, key: str, chunk_size: int = 64 * 1024) -> Iterator[bytes]: ...


class S3BlobStore:
    def __init__(
        self,
        *,
        endpoint_url: str | None,
        bucket: str,
        access_key: str | None,
        secret_key: str | None,
    ) -> None:
        self._bucket = bucket
        # Bounded timeouts: a stalled store must fail fast (the task retries), not hold a
        # worker slot for a minute and block every case queued behind it.
        self._s3 = boto3.client(
            "s3",
            endpoint_url=endpoint_url,
            region_name="us-east-1",
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            config=Config(
                connect_timeout=5, read_timeout=30, retries={"max_attempts": 3, "mode": "standard"}
            ),
        )

    def put(self, key: str, data: bytes, content_type: str) -> None:
        self._s3.put_object(Bucket=self._bucket, Key=key, Body=data, ContentType=content_type)

    def stream(self, key: str, chunk_size: int = 64 * 1024) -> Iterator[bytes]:
        body = self._s3.get_object(Bucket=self._bucket, Key=key)["Body"]
        yield from body.iter_chunks(chunk_size)


class MemoryBlobStore:
    """Tests only."""

    def __init__(self) -> None:
        self.objects: dict[str, tuple[bytes, str]] = {}
        self._lock = threading.Lock()

    def put(self, key: str, data: bytes, content_type: str) -> None:
        with self._lock:
            self.objects[key] = (data, content_type)

    def stream(self, key: str, chunk_size: int = 64 * 1024) -> Iterator[bytes]:
        data = self.objects[key][0]
        for i in range(0, len(data), chunk_size):
            yield data[i : i + chunk_size]


def object_key(tenant_id: object, request_id: object, artifact_id: object, ext: str) -> str:
    return f"tenants/{tenant_id}/requests/{request_id}/{artifact_id}.{ext}"
