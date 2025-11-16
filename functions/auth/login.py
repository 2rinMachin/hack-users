from datetime import datetime, timedelta, timezone

import boto3
from pydantic import BaseModel

from common import auth, parse_body, response
from schemas import SessionToken, User


class LoginRequest(BaseModel):
    email: str
    password: str


dynamodb = boto3.resource("dynamodb")
users = dynamodb.Table("hack-users")
session_tokens = dynamodb.Table("hack-user-tokens")


def handler(event, context):
    data, err = parse_body(LoginRequest, event)
    if err != None:
        return err

    assert data != None

    resp = users.query(
        IndexName="email-idx",
        KeyConditionExpression="email = :email",
        ExpressionAttributeValues={":email": data.email},
        Limit=1,
    )

    if resp["Count"] == 0:
        return response(401, {"message": "Invalid credentials."})

    items: list[dict] = resp["Items"]
    user = User(**items[0])

    if not auth.verify_password(data.password, user.password):
        return response(401, {"message": "Invalid credentials."})

    token_value = auth.generate_session_token()
    expires_at = datetime.now(timezone.utc) + timedelta(hours=8)

    token = SessionToken(
        token=token_value,
        user_id=user.id,
        expires_at=expires_at.isoformat(),
    )

    session_tokens.put_item(Item=token.model_dump())

    return response(200, {"token": token_value})
