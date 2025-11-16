import base64
import hashlib
import os
import secrets
from datetime import datetime, timezone

import boto3

from schemas import SessionToken, User

dynamodb = boto3.resource("dynamodb")
users = dynamodb.Table("hack-users")
session_tokens = dynamodb.Table("hack-user-tokens")


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    return base64.b64encode(salt + dk).decode()


def verify_password(password: str, stored: str) -> bool:
    raw = base64.b64decode(stored)
    salt, dk = raw[:16], raw[16:]
    new_dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    return new_dk == dk


def generate_session_token() -> str:
    return secrets.token_urlsafe(64)


def verify_session_token(token: str) -> User | None:
    if token == "":
        return None

    resp = session_tokens.get_item(Key={"token": token})
    item: dict | None = resp.get("Item")

    if item == None:
        return None

    token_data = SessionToken(**item)
    expires_at = datetime.fromisoformat(token_data.expires_at)

    if expires_at < datetime.now(timezone.utc):
        return None

    user_resp = users.get_item(Key={"id": token_data.user_id})
    user_item: dict | None = user_resp.get("Item")

    if user_item == None:
        return None

    return User(**user_item)


def unauthorized(event):
    return {
        "principalId": "user",
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "execute-api:Invoke",
                    "Effect": "Deny",
                    "Resource": event["methodArn"],
                }
            ],
        },
    }


def authorized(event, user: User):
    return {
        "principalId": user.id,
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "execute-api:Invoke",
                    "Effect": "Allow",
                    "Resource": event["methodArn"],
                }
            ],
        },
        "context": user.model_dump(),
    }
