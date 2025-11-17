import boto3

from common import auth
from common.auth import verify_session_token
from schemas import UserRole

dynamodb = boto3.resource("dynamodb")
users = dynamodb.Table("hack-users")
session_tokens = dynamodb.Table("hack-user-tokens")


def handler(event, context):
    print("headers: ", event["headers"])
    authorization = str(event["headers"]["Authorization"])
    token = authorization.split(" ")[1]

    user = verify_session_token(token)

    if user == None:
        return auth.unauthorized(event)

    if user.role != UserRole.staff and user.role != UserRole.authority:
        return auth.unauthorized(event)

    return auth.authorized(event, user)
