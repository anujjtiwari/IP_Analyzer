from .key_management import get_active_private_key, get_active_public_key
from rest_framework.response import Response
from rest_framework import status
from bson.objectid import ObjectId
import jwt
import json
import datetime


def get_token(payload):
    private_key_pem = get_active_private_key()
    return jwt.encode(payload, private_key_pem, algorithm="EdDSA")


def get_payload(request):
    if "authToken" not in request.COOKIES:
        return (
            Response(
                json.dumps({"message": "No Auth Token!"}),
                status=status.HTTP_401_UNAUTHORIZED,
            ),
            False,
        )

    token = request.COOKIES["authToken"]
    try:
        public_key_pem = get_active_public_key()
        return jwt.decode(token, public_key_pem, algorithms=["EdDSA"]), True
    except jwt.ExpiredSignatureError:
        return (
            Response(
                json.dumps({"message": "Token has expired!"}),
                status=status.HTTP_401_UNAUTHORIZED,
            ),
            False,
        )
    except jwt.InvalidTokenError:
        return (
            Response(
                json.dumps({"message": "Invalid token!"}),
                status=status.HTTP_401_UNAUTHORIZED,
            ),
            False,
        )
    except Exception as e:
        return (
            Response(
                json.dumps({"message": "Invalid token!"}),
                status=status.HTTP_401_UNAUTHORIZED,
            ),
            False,
        )


# , is_verified:bool
def create_token(user_id: any, purpose: str) -> str:
    payload = {
        "user_id": str(user_id),
        "purpose": purpose,
        # "is_verified": is_verified,
        "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=30),
        "iat": datetime.datetime.now(datetime.timezone.utc),
    }

    return get_token(payload)


def verify_token_user(request, purpose_db):
    payload, is_valid = get_payload(request)
    if not is_valid:
        return None, None, payload

    if (
        "user_id" not in payload
        or "purpose" not in payload
        or payload["purpose"] not in purpose_db
    ):
        return (
            None,
            None,
            Response(
                json.dumps({"message": "Invalid Token"}),
                status=status.HTTP_401_UNAUTHORIZED,
            ),
        )

    user_id = ObjectId(payload["user_id"])
    user = purpose_db[payload["purpose"]].find_one({"_id": user_id})

    if not user:
        return (
            None,
            None,
            Response(
                json.dumps({"message": "Invalid Token"}),
                status=status.HTTP_401_UNAUTHORIZED,
            ),
        )
    elif user["is_locked"]:
        return (
            None,
            None,
            Response(
                json.dumps({"message": "Account Locked by Admin"}),
                status=status.HTTP_401_UNAUTHORIZED,
            ),
        )

    return user, payload, None


def verify_token_admin(request, purpose_db):
    user, payload, error_response = verify_token_user(request, purpose_db)

    if user is None:
        return user, payload, error_response

    if not user["is_admin"]:
        return (
            None,
            None,
            Response(
                json.dumps({"message": "Unauthorized User"}),
                status=status.HTTP_401_UNAUTHORIZED,
            ),
        )

    return user, payload, None
