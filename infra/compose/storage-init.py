"""Create the private evidence bucket in the local S3 stand-in. No public policy is ever attached (ADR-0007)."""

import os
import time

import boto3
from botocore.exceptions import ClientError, EndpointConnectionError

s3 = boto3.client(
    "s3",
    endpoint_url=os.environ["IDP_S3_ENDPOINT_URL"],
    aws_access_key_id=os.environ["IDP_S3_ACCESS_KEY_ID"],
    aws_secret_access_key=os.environ["IDP_S3_SECRET_ACCESS_KEY"],
    region_name="us-east-1",
)
bucket = os.environ["IDP_S3_BUCKET"]
for attempt in range(30):
    try:
        s3.head_bucket(Bucket=bucket)
        print(f"bucket {bucket} exists")
        break
    except ClientError as exc:
        if exc.response["Error"]["Code"] in {"404", "NoSuchBucket"}:
            s3.create_bucket(Bucket=bucket)
            print(f"created bucket {bucket}")
            break
        raise
    except EndpointConnectionError:
        time.sleep(1)
else:
    raise SystemExit("object storage unreachable")
