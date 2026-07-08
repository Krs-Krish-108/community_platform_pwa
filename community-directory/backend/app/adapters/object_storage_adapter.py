"""
Object storage adapter — interfaces with private S3-compatible object storage (e.g., Cloudflare R2).
Falls back to mock signed URL generation when credentials are not configured in settings.
"""
from botocore.config import Config
import boto3

from app.core.config import get_settings


class ObjectStorageAdapter:
    def __init__(self):
        self.settings = get_settings()
        # Fallback to mock if keys are missing
        self.use_mock = not (
            self.settings.object_storage_access_key and self.settings.object_storage_secret_key
        )

    def generate_presigned_upload_url(
        self, storage_key: str, content_type: str, expires_in: int = 3600
    ) -> str:
        """Generate a presigned PUT URL for uploading file bytes directly from the client."""
        if self.use_mock:
            return f"http://mock-storage.local/{self.settings.object_storage_bucket}/{storage_key}?action=upload"

        s3 = boto3.client(
            "s3",
            endpoint_url=self.settings.object_storage_endpoint or None,
            aws_access_key_id=self.settings.object_storage_access_key,
            aws_secret_access_key=self.settings.object_storage_secret_key,
            config=Config(signature_version="s3v4"),
        )
        return s3.generate_presigned_url(
            ClientMethod="put_object",
            Params={
                "Bucket": self.settings.object_storage_bucket,
                "Key": storage_key,
                "ContentType": content_type,
            },
            ExpiresIn=expires_in,
        )

    def generate_presigned_download_url(
        self, storage_key: str, expires_in: int = 3600
    ) -> str:
        """Generate a presigned GET URL for secure downloading/viewing."""
        if self.use_mock:
            return f"http://mock-storage.local/{self.settings.object_storage_bucket}/{storage_key}?action=download"

        s3 = boto3.client(
            "s3",
            endpoint_url=self.settings.object_storage_endpoint or None,
            aws_access_key_id=self.settings.object_storage_access_key,
            aws_secret_access_key=self.settings.object_storage_secret_key,
            config=Config(signature_version="s3v4"),
        )
        return s3.generate_presigned_url(
            ClientMethod="get_object",
            Params={
                "Bucket": self.settings.object_storage_bucket,
                "Key": storage_key,
            },
            ExpiresIn=expires_in,
        )
