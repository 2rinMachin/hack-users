import boto3

from common.auth import verify_session_token
from schemas import User, UserResponseDto

dynamodb = boto3.resource("dynamodb")
users = dynamodb.Table("hack-users")
session_tokens = dynamodb.Table("hack-user-tokens")


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


def handler(event, context):
    authorization = str(event["headers"]["Authorization"])
    token = authorization.split(" ")[1]

    user = verify_session_token(token)

    if user == None:
        return unauthorized(event)

    return authorized(event, user)
