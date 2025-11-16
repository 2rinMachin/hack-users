import boto3

from common import auth
from common.auth import verify_session_token
from schemas import UserRole

dynamodb = boto3.resource("dynamodb")
users = dynamodb.Table("hack-users")
session_tokens = dynamodb.Table("hack-user-tokens")


def handler(event, context):
    authorization = str(event["headers"]["Authorization"])
    token = authorization.split(" ")[1]

    user = verify_session_token(token)

    if user == None or user.role != UserRole.staff or user.role != UserRole.authority:
        return auth.unauthorized(event)

    return auth.authorized(event, user)
