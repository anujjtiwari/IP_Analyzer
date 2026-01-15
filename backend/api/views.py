from types import NoneType
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from .utils import send_otp, hash_password, check_password, compute_results
from .token_management import (
    create_token,
    verify_token_user,
    verify_token_admin,
)
from . import database as db
from bson.objectid import ObjectId
import datetime
import json

class user_sign_in(APIView):
    def post(self, request):
        data = request.data
        if "email" not in data or "password" not in data:
            return Response(
                json.dumps({"message": "Invalid data"}),
                status=status.HTTP_400_BAD_REQUEST,
            )

        data["email"] = data["email"].strip()
        data["password"] = data["password"].strip()
        user = db.collection_handle_users.find_one({"email": data["email"]})

        if user and check_password(
            data["password"].encode("utf8"), user["password"].encode("utf8")
        ):
            otp = send_otp("Sign IN", data["email"])
            if otp is None:
                return Response(
                    json.dumps({"message": "Internal Server Error!"}),
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )
            else:
                otp = hash_password(otp)
                db.collection_handle_users.update_one(
                    {"_id": user["_id"]},
                    {"$set": {"otp": otp}},
                )

            try:
                token = create_token(user["_id"], "SIGN_IN")
                response = Response(
                    json.dumps({"messsage": "OTP SENT!"}),
                    status=status.HTTP_200_OK,
                )
                expires = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
                    minutes=30
                )
                response.set_cookie(
                    "authToken",
                    token,
                    httponly=True,
                    secure=True,
                    samesite="Strict",
                    expires=expires,
                )
                return response

            except Exception as e:
                return Response(
                    json.dumps({"message": str(e)}),
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )

        return Response(
            json.dumps({"message": "Incorrect Credentials"}),
            status=status.HTTP_400_BAD_REQUEST,
        )


class user_sign_out(APIView):
    def get(self, request):
        response = Response(
            json.dumps({"message": "User Successfully Logged Out!"}),
            status=status.HTTP_200_OK,
        )
        response.delete_cookie("authToken")
        return response


class forgot_password(APIView):
    def post(self, request):
        if (
            request.data is None
            or "email" not in request.data
            or not isinstance(request.data["email"], str)
        ):
            return Response(
                json.dumps({"message": "Bad Request"}),
                status=status.HTTP_400_BAD_REQUEST,
            )

        request.data["email"] = request.data["email"].strip()
        user = db.collection_handle_users.find_one({"email": request.data["email"]})

        if user is None:
            return Response(
                json.dumps({"message": "User Not Found!"}),
                status=status.HTTP_400_BAD_REQUEST,
            )

        otp = send_otp("Reset Password", request.data["email"])

        if otp is None:
            return Response(
                json.dumps({"message": "Internal Server Error!"}),
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        otp = hash_password(otp)
        db.collection_handle_users.update_one(
            {"_id": user["_id"]},
            {"$set": {"otp": otp}},
        )

        try:
            token = create_token(user["_id"], "RESET_PASSWORD")
            response = Response(
                json.dumps({"messsage": "OTP SENT!"}),
                status=status.HTTP_200_OK,
            )
            expires = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
                minutes=30
            )
            response.set_cookie(
                "authToken",
                token,
                httponly=True,
                secure=True,
                samesite="Strict",
                expires=expires,
            )
            return response

        except Exception as e:
            return Response(
                json.dumps({"message": str(e)}),
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class otp_verify(APIView):
    def post(self, request):
        user, payload, error_response = verify_token_user(
            request,
            {
                "SIGN_UP": db.collection_handle_temp_users,
                "SIGN_IN": db.collection_handle_users,
                "RESET_PASSWORD": db.collection_handle_users,
                "EMAIL_CHANGE": db.collection_handle_users,
            },
        )

        if user is None:
            return error_response

        data = request.data
        data["otp"] = data["otp"].strip()

        if user["otp"] and check_password(
            data["otp"].encode("utf8"), user["otp"].encode("utf8")
        ):
            if payload["purpose"] == "SIGN_UP":
                db.collection_handle_users.insert_one(
                    {
                        "name": user["name"],
                        "email": user["email"],
                        "password": user["password"],
                        "otp": None,
                        "is_admin": False,
                        "is_locked": False,
                    }
                )
                db.collection_handle_temp_users.delete_one({"_id": user["_id"]})

            elif payload["purpose"] in ["SIGN_IN", "RESET_PASSWORD", "EMAIL_CHANGE"]:
                db.collection_handle_users.update_one(
                    {"_id": user["_id"]},
                    {"$set": {"otp": None}},
                )

            response = Response(
                json.dumps({"message": "OTP Verified!"}), status=status.HTTP_200_OK
            )

            if payload["purpose"] == "SIGN_UP":
                response.delete_cookie("authToken")

            elif payload["purpose"] == "SIGN_IN":
                token = create_token(user["_id"], "AUTH")
                expires = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
                    minutes=30
                )
                response.set_cookie(
                    "authToken",
                    token,
                    httponly=True,
                    secure=True,
                    samesite="Strict",
                    expires=expires,
                )
            elif payload["purpose"] == "RESET_PASSWORD":
                token = create_token(user["_id"], "SET_PASSWORD")
                expires = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
                    minutes=30
                )
                response.set_cookie(
                    "authToken",
                    token,
                    httponly=True,
                    secure=True,
                    samesite="Strict",
                    expires=expires,
                )
            elif payload["purpose"] == "EMAIL_CHANGE":
                token = create_token(user["_id"], "SET_EMAIL")
                expires = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
                    minutes=30
                )
                response.set_cookie(
                    "authToken",
                    token,
                    httponly=True,
                    secure=True,
                    samesite="Strict",
                    expires=expires,
                )

            return response

        else:
            return Response(
                json.dumps({"message": "Incorrect OTP!"}),
                status=status.HTTP_401_UNAUTHORIZED,
            )


class set_password(APIView):
    def post(self, request):
        user, payload, error_response = verify_token_user(
            request,
            {"SET_PASSWORD": db.collection_handle_users},
        )

        if user is None:
            return error_response

        if (
            request.data is None
            or "password" not in request.data
            or not isinstance(request.data["password"], str)
        ):
            return Response(
                json.dumps({"message": "Bad Request"}),
                status=status.HTTP_400_BAD_REQUEST,
            )

        request.data["password"] = hash_password(request.data["password"])
        result = db.collection_handle_users.update_one(
            {"_id": user["_id"]}, {"$set": {"password": request.data["password"]}}
        )

        if result.modified_count > 0:
            response = Response(
                json.dumps({"message": "Password changed!"}), status=status.HTTP_200_OK
            )
            response.delete_cookie("authToken")
            return response

        else:
            return Response(
                json.dumps({"message": "Account Not Found!"}),
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class check_set_password_token(APIView):
    def get(self, request):
        user, payload, error_response = verify_token_user(
            request,
            {"SET_PASSWORD": db.collection_handle_users},
        )

        if user is None:
            return error_response

        return Response(
            json.dumps({"message": "Valid Token"}), status=status.HTTP_200_OK
        )


class check_sign_in_token(APIView):
    def get(self, request):
        user, payload, error_response = verify_token_user(
            request,
            {"AUTH": db.collection_handle_users},
        )

        if user is None:
            return error_response

        return Response(
            json.dumps({"message": "Valid Token"}), status=status.HTTP_200_OK
        )


class user_sign_up(APIView):
    def post(self, request):
        data = request.data

        if "name" not in data or "email" not in data or "password" not in data:
            return Response(
                json.dumps({"message": "Invalid data"}),
                status=status.HTTP_400_BAD_REQUEST,
            )

        data["name"] = data["name"].strip()
        data["email"] = data["email"].strip()
        data["password"] = data["password"].strip()

        if db.collection_handle_users.find_one({"email": data["email"]}):
            return Response(
                json.dumps({"message": "Email ID Already Exists!"}),
                status=status.HTTP_400_BAD_REQUEST,
            )

        otp = send_otp("Sign UP", data["email"])
        if otp is None:
            return Response(
                json.dumps({"message": "Internal Server Error!"}),
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
        else:
            otp = hash_password(otp)

        data["password"] = hash_password(data["password"])
        temp_user = db.collection_handle_temp_users.find_one({"email": data["email"]})
        temp_user_id = ""

        if temp_user:
            temp_user["name"] = data["name"]
            temp_user["password"] = data["password"]
            temp_user["otp"] = otp
            db.collection_handle_temp_users.update_one(
                {"_id": temp_user["_id"]},
                {
                    "$set": {
                        "name": data["name"],
                        "password": data["password"],
                        "otp": otp,
                    }
                },
            )
            temp_user_id = temp_user["_id"]
        else:
            temp_user = db.collection_handle_temp_users.insert_one(
                {
                    "name": data["name"],
                    "email": data["email"],
                    "password": data["password"],
                    "otp": otp,
                    "is_locked": False,
                }
            )
            temp_user_id = temp_user.inserted_id

        try:
            token = create_token(temp_user_id, "SIGN_UP")
            response = Response(
                json.dumps({"messsage": "OTP Generated!"}), status=status.HTTP_200_OK
            )
            expires = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
                minutes=30
            )
            response.set_cookie(
                "authToken",
                token,
                httponly=True,
                secure=True,
                samesite="Strict",
                expires=expires,
            )
            return response

        except Exception as e:
            return Response(
                json.dumps({"message": str(e)}),
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class resend_otp(APIView):
    def get(self, request):
        user, payload, error_response = verify_token_user(
            request,
            {
                "SIGN_UP": db.collection_handle_temp_users,
                "SIGN_IN": db.collection_handle_users,
                "EMAIL_CHANGE": db.collection_handle_users,
                "RESET_PASSWORD": db.collection_handle_users,
            },
        )

        if user is None:
            return error_response
        
        otp = None

        if payload["purpose"] == "SIGN_UP":
            otp = send_otp("Sign UP", user["email"])
        elif payload["purpose"] == "SIGN_IN":
            otp = send_otp("Sign IN", user["email"])
        elif payload["purpose"] == "EMAIL_CHANGE":
            otp = send_otp("Update Email", user["email"])
        elif payload["purpose"] == "RESET_PASSWORD":
            otp = send_otp("Reset Password", user["email"])

        if otp is None:
            return Response(
                json.dumps({"message": "Internal Server Error!"}),
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
        else:
            otp = hash_password(otp)
            if payload["purpose"] in ["SIGN_IN", "EMAIL_CHANGE", "RESET_PASSWORD"]:
                db.collection_handle_users.update_one(
                    {"_id": user["_id"]},
                    {"$set": {"otp": otp}},
                )
            else:
                db.collection_handle_temp_users.update_one(
                    {"_id": user["_id"]},
                    {"$set": {"otp": otp}},
                )

        return Response(
            json.dumps({"messsage": "OTP Sent!"}),
            status=status.HTTP_200_OK,
        )


class admin_name(APIView):
    def get(self, request):
        user, payload, error_response = verify_token_admin(
            request, {"AUTH": db.collection_handle_users}
        )

        if user is None:
            return error_response

        return Response(
            json.dumps({"admin_name": user["name"]}), status=status.HTTP_200_OK
        )


class user_list(APIView):
    def get(self, request):
        user, payload, error_response = verify_token_admin(
            request, {"AUTH": db.collection_handle_users}
        )

        if user is None:
            return error_response

        users = list(
            db.collection_handle_users.find(
                {"_id": {"$ne": user["_id"]}}, {"password": 0, "otp": 0}
            )
        )

        for doc_user in users:
            doc_user["_id"] = str(doc_user["_id"])

        return Response(json.dumps({"user_list": users}), status=status.HTTP_200_OK)


class user_name(APIView):
    def get(self, request):
        user, payload, error_response = verify_token_user(
            request, {"AUTH": db.collection_handle_users}
        )

        if user is None:
            return error_response
        
        response = Response(
            json.dumps({"user_name": user["name"]}), status=status.HTTP_200_OK
        )

        time_remaining = datetime.datetime.fromtimestamp(payload['exp'], datetime.timezone.utc) - datetime.datetime.now(datetime.timezone.utc)

        if datetime.timedelta(seconds=1) < time_remaining and time_remaining < datetime.timedelta(minutes=15):
            token = create_token(user["_id"], "AUTH")
            expires = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
                minutes=30
            )
            response.set_cookie(
                "authToken",
                token,
                httponly=True,
                secure=True,
                samesite="Strict",
                expires=expires,
            )

        return response


class is_admin(APIView):
    def get(self, request):
        user, payload, error_response = verify_token_admin(
            request, {"AUTH": db.collection_handle_users}
        )

        if user is None:
            return error_response

        return Response(json.dumps({"message": "Yes"}), status=status.HTTP_200_OK)


class compute(APIView):
    def post(self, request):
        user, payload, error_response = verify_token_user(
            request, {"AUTH": db.collection_handle_users}
        )

        if user is None:
            return error_response

        print(request.data)
        results, results_summary = compute_results(
            user["email"], request.data, db.collection_handle_queries
        )

        return Response(
            json.dumps({"results": results, "results_summary": results_summary}),
            status=status.HTTP_200_OK,
        )


class delete_user(APIView):
    def post(self, request):
        user, payload, error_response = verify_token_user(
            request, {"AUTH": db.collection_handle_users}
        )

        if user is None:
            return error_response

        print(request.data)
        if (
            request.data is None
            or "user_id" not in request.data
            or not isinstance(request.data["user_id"], (str, NoneType))
        ):
            return Response(
                json.dumps({"message": "Bad Request"}),
                status=status.HTTP_400_BAD_REQUEST,
            )

        user_to_delete = None

        if request.data["user_id"] is None:
            user_to_delete = user

        elif user["is_admin"]:
            request.data["user_id"] = ObjectId(request.data["user_id"])

            user_to_delete = db.collection_handle_users.find_one(
                {"_id": request.data["user_id"]}
            )
            if not user_to_delete:
                return Response(
                    json.dumps({"message": "User Not Found"}),
                    status=status.HTTP_400_BAD_REQUEST,
                )
        else:
            return Response(
                json.dumps({"message": "Unauthorized!"}),
                status=status.HTTP_401_UNAUTHORIZED,
            )

        if user_to_delete["is_admin"]:
            admins = list(db.collection_handle_users.find({"is_admin": True}))
            if len(admins) == 1:
                return Response(
                    json.dumps({"message": "Single Admin Account Can't Be Deleted!"}),
                    status=status.HTTP_401_UNAUTHORIZED,
                )

        result = db.collection_handle_users.delete_one({"_id": user_to_delete["_id"]})

        if result.deleted_count > 0:
            response = Response(
                json.dumps({"message": "User Account Deleted!"}),
                status=status.HTTP_200_OK,
            )

            if request.data["user_id"] is None:
                response.delete_cookie("authToken")

            return response
        else:
            return Response(
                json.dumps({"message": "Internal Server Error"}),
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class lock_user(APIView):
    def post(self, request):
        user, payload, error_response = verify_token_admin(
            request, {"AUTH": db.collection_handle_users}
        )

        if not user:
            return error_response

        if (
            request.data is None
            or "user_id" not in request.data
            or not isinstance(request.data["user_id"], str)
        ):
            return Response(
                json.dumps({"message": "Bad Request"}),
                status=status.HTTP_400_BAD_REQUEST,
            )

        request.data["user_id"] = ObjectId(request.data["user_id"])
        user_to_lock = db.collection_handle_users.find_one(
            {"_id": request.data["user_id"]}
        )

        if not user_to_lock:
            return Response(
                json.dumps({"message": "User Account Not Found"}),
                status=status.HTTP_400_BAD_REQUEST,
            )

        if user_to_lock["is_admin"]:
            return Response(
                json.dumps({"message": "Can't Lock An Admin Account!"}),
                status=status.HTTP_401_UNAUTHORIZED,
            )

        result = db.collection_handle_users.update_one(
            {"_id": user_to_lock["_id"]}, {"$set": {"is_locked": True}}
        )

        if result.modified_count > 0:
            return Response(
                json.dumps({"message": "User Account Locked!"}),
                status=status.HTTP_200_OK,
            )
        else:
            return Response(
                json.dumps({"message": "Account Not Found!"}), status=status.HTTP_200_OK
            )


class unlock_user(APIView):
    def post(self, request):
        user, payload, error_response = verify_token_admin(
            request, {"AUTH": db.collection_handle_users}
        )

        if not user:
            return error_response

        if (
            request.data is None
            or "user_id" not in request.data
            or not isinstance(request.data["user_id"], str)
        ):
            return Response(
                json.dumps({"message": "Bad Request"}),
                status=status.HTTP_400_BAD_REQUEST,
            )

        request.data["user_id"] = ObjectId(request.data["user_id"])
        result = db.collection_handle_users.find_one_and_update(
            {"_id": request.data["user_id"]}, {"$set": {"is_locked": False}}
        )

        if result:
            return Response(
                json.dumps({"message": "User Account Unlocked!"}),
                status=status.HTTP_200_OK,
            )
        else:
            return Response(
                json.dumps({"message": "Account Not Found!"}), status=status.HTTP_200_OK
            )


class make_admin(APIView):
    def post(self, request):
        user, payload, error_response = verify_token_admin(
            request, {"AUTH": db.collection_handle_users}
        )

        if not user:
            return error_response

        if (
            request.data is None
            or "user_id" not in request.data
            or not isinstance(request.data["user_id"], str)
        ):
            return Response(
                json.dumps({"message": "Bad Request"}),
                status=status.HTTP_400_BAD_REQUEST,
            )

        request.data["user_id"] = ObjectId(request.data["user_id"])
        user_to_make_admin = db.collection_handle_users.find_one(
            {"_id": request.data["user_id"]}
        )

        if not user_to_make_admin:
            return Response(
                json.dumps({"message": "User Account Not Found"}),
                status=status.HTTP_400_BAD_REQUEST,
            )

        if user_to_make_admin["is_locked"]:
            return Response(
                json.dumps(
                    {"message": "Can't Grant Admin Privileges to a Locked Account!"}
                ),
                status=status.HTTP_401_UNAUTHORIZED,
            )

        result = db.collection_handle_users.update_one(
            {"_id": user_to_make_admin["_id"]}, {"$set": {"is_admin": True}}
        )

        if result.modified_count > 0:
            return Response(
                json.dumps({"message": "Admin Privileges Granted to User Account!"}),
                status=status.HTTP_200_OK,
            )
        else:
            return Response(
                json.dumps({"message": "Account Not Found!"}), status=status.HTTP_200_OK
            )


class revoke_admin(APIView):
    def post(self, request):
        user, payload, error_response = verify_token_admin(
            request, {"AUTH": db.collection_handle_users}
        )

        if not user:
            return error_response

        if (
            request.data is None
            or "user_id" not in request.data
            or not isinstance(request.data["user_id"], str)
        ):
            return Response(
                json.dumps({"message": "Bad Request"}),
                status=status.HTTP_400_BAD_REQUEST,
            )

        request.data["user_id"] = ObjectId(request.data["user_id"])
        result = db.collection_handle_users.find_one_and_update(
            {"_id": request.data["user_id"]}, {"$set": {"is_admin": False}}
        )

        if result:
            return Response(
                json.dumps({"message": "Admin Privileges Revoked from User Account"}),
                status=status.HTTP_200_OK,
            )
        else:
            return Response(
                json.dumps({"message": "Account Not Found!"}), status=status.HTTP_200_OK
            )


class user_info(APIView):
    def get(self, request):
        user, payload, error_response = verify_token_user(
            request, {"AUTH": db.collection_handle_users}
        )

        if not user:
            return error_response

        return Response(
            json.dumps({"name": user["name"], "email": user["email"]}),
            status=status.HTTP_200_OK,
        )


class update_name(APIView):
    def post(self, request):
        user, payload, error_response = verify_token_user(
            request, {"AUTH": db.collection_handle_users}
        )

        if not user:
            return error_response

        if (
            request.data is None
            or "name" not in request.data
            or not isinstance(request.data["name"], str)
        ):
            return Response(
                json.dumps({"message": "Bad Request"}),
                status=status.HTTP_400_BAD_REQUEST,
            )

        request.data["name"] = request.data["name"].strip()
        if not request.data["name"]:
            return Response(
                json.dumps({"message": "Bad Request"}),
                status=status.HTTP_400_BAD_REQUEST,
            )

        result = db.collection_handle_users.update_one(
            {"_id": user["_id"]}, {"$set": {"name": request.data["name"]}}
        )

        if result.modified_count > 0:
            return Response(
                json.dumps({"message": "User Name Updated!"}),
                status=status.HTTP_200_OK,
            )
        else:
            return Response(
                json.dumps({"message": "Account Not Found!"}), status=status.HTTP_200_OK
            )


class update_email(APIView):
    def post(self, request):
        user, payload, error_response = verify_token_user(
            request, {"AUTH": db.collection_handle_users}
        )

        if not user:
            return error_response

        if (
            request.data is None
            or "email" not in request.data
            or not isinstance(request.data["email"], str)
        ):
            return Response(
                json.dumps({"message": "Bad Request"}),
                status=status.HTTP_400_BAD_REQUEST,
            )

        if db.collection_handle_users.find_one({"email": request.data["email"]}):
            return Response(
                json.dumps({"message": "Email Is Already Registered!"}),
                status=status.HTTP_400_BAD_REQUEST,
            )

        otp = send_otp("Email Change", request.data["email"])
        if otp is None:
            return Response(
                json.dumps({"message": "Internal Server Error!"}),
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
        else:
            otp = hash_password(otp)
            result = db.collection_handle_users.update_one(
                {"_id": user["_id"]},
                {
                    "$set": {
                        "otp": otp,
                    }
                },
            )

            if result.matched_count < 1:
                return Response(
                    json.dumps({"message": str(e)}),
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )

        try:
            token = create_token(user["_id"], "EMAIL_CHANGE")
            response = Response(
                json.dumps({"messsage": "OTP Generated!"}), status=status.HTTP_200_OK
            )
            expires = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
                minutes=30
            )
            response.set_cookie(
                "authToken",
                token,
                httponly=True,
                secure=True,
                samesite="Strict",
                expires=expires,
            )
            return response

        except Exception as e:
            return Response(
                json.dumps({"message": str(e)}),
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class set_email(APIView):
    def post(self, request):
        user, payload, error_response = verify_token_user(
            request,
            {"SET_EMAIL": db.collection_handle_users},
        )

        if user is None:
            return error_response

        if (
            request.data is None
            or "email" not in request.data
            or not isinstance(request.data["email"], str)
        ):
            return Response(
                json.dumps({"message": "Bad Request"}),
                status=status.HTTP_400_BAD_REQUEST,
            )

        if db.collection_handle_users.find_one({"email": request.data["email"]}):
            return Response(
                json.dumps({"message": "Email Is Already Registered!"}),
                status=status.HTTP_400_BAD_REQUEST,
            )

        result = db.collection_handle_users.update_one(
            {"_id": user["_id"]}, {"$set": {"email": request.data["email"]}}
        )

        if result.modified_count > 0:
            response = Response(
                json.dumps({"message": "Email Updated!"}), status=status.HTTP_200_OK
            )
            response.delete_cookie("authToken")
            return response

        else:
            return Response(
                json.dumps({"message": "Account Not Found!"}),
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class update_password(APIView):
    def post(self, request):
        user, payload, error_response = verify_token_user(
            request, {"AUTH": db.collection_handle_users}
        )

        if not user:
            return error_response

        if (
            request.data is None
            or "oldPassword" not in request.data
            or "newPassword" not in request.data
            or not isinstance(request.data["oldPassword"], str)
            or not isinstance(request.data["newPassword"], str)
        ):
            return Response(
                json.dumps({"message": "Bad Request"}),
                status=status.HTTP_400_BAD_REQUEST,
            )

        request.data["oldPassword"] = request.data["oldPassword"].strip()
        request.data["newPassword"] = request.data["newPassword"].strip()

        if not request.data["oldPassword"] or not request.data["newPassword"]:
            return Response(
                json.dumps({"message": "Bad Request"}),
                status=status.HTTP_400_BAD_REQUEST,
            )

        request.data["newPassword"] = hash_password(request.data["newPassword"])

        if check_password(
            request.data["oldPassword"].encode("utf8"), user["password"].encode("utf8")
        ):
            result = db.collection_handle_users.update_one(
                {"_id": user["_id"]},
                {"$set": {"password": request.data["newPassword"]}},
            )

            if result.modified_count > 0:
                response = Response(
                    json.dumps({"message": "User Password Updated!"}),
                    status=status.HTTP_200_OK,
                )
                return response

            else:
                return Response(
                    json.dumps({"message": "Account Not Found!"}),
                    status=status.HTTP_200_OK,
                )
        else:
            return Response(
                json.dumps({"message": "Incorrect Password"}),
                status=status.HTTP_400_BAD_REQUEST,
            )
