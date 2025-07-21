from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from .serializers import (
    RegisterSerializer,
    LoginSerializer,
    ChangePasswordSerializer,
    ForgotPasswordSerializer,
    ResetPasswordSerializer,
)
from .models import CustomUser
import logging


from django.core.mail import send_mail
from django.core.cache import cache
import random


# Set up logging
logger = logging.getLogger(__name__)


# Register a new user
@api_view(["POST"])
@permission_classes([AllowAny])
def register_user(request):
    username = request.data.get("username")
    email = request.data.get("email")
    password = request.data.get("password")
    role = request.data.get("role")  # Optional, only used if with_role=devtr

    if not username or not email or not password:
        return Response(
            {"error": "Please provide username, email, and password"},
            status=status.HTTP_400_BAD_REQUEST,
        )

    if User.objects.filter(username=username).exists():
        return Response(
            {"error": "Username already exists"}, status=status.HTTP_400_BAD_REQUEST
        )
    
    if User.objects.filter(email=email).exists():
        return Response(
            {"error": "Email already exists"}, status=status.HTTP_400_BAD_REQUEST
        )

    # Detect if role-based registration is requested
    with_role = request.query_params.get("with_role", "false").lower() == "devtr"

    user = User.objects.create_user(username=username, email=email, password=password)

    # Role defaults
    is_superadmin = False
    is_admin = False
    is_user = True  # Default role
    user.is_staff = False
    user.is_superuser = False

    if with_role:
        if not role:
            return Response(
                {"error": "Role is required when with_role=devtr"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if role.lower() == "superadmin":
            is_superadmin = True
            is_admin = False
            is_user = False
            user.is_staff = True
            user.is_superuser = True
        elif role.lower() == "admin":
            is_superadmin = False
            is_admin = True
            is_user = False
            user.is_staff = True
            user.is_superuser = False
        elif role.lower() == "user":
            is_superadmin = False
            is_admin = False
            is_user = True
            user.is_staff = True
            user.is_superuser = False
        else:
            return Response(
                {"error": "Invalid role. Choose superadmin, admin, or user"},
                status=status.HTTP_400_BAD_REQUEST,
            )

    user.save()

    # Assign to CustomUser model
    custom_user = CustomUser.objects.get(user=user)
    custom_user.is_superadmin = is_superadmin
    custom_user.is_admin = is_admin
    custom_user.is_user = is_user
    custom_user.save()

    # refresh = RefreshToken.for_user(user)

    return Response(
        {
            # 'username': user.username,
            # 'email': user.email,
            # 'role': 'superadmin' if is_superadmin else 'admin' if is_admin else 'user',
            # 'refresh': str(refresh),
            # 'access': str(refresh.access_token),
            "msg": "User registered successfully",
        },
        status=status.HTTP_201_CREATED,
    )


# Login a user
@api_view(["POST"])
@permission_classes([AllowAny])
def login_user(request):
    email = request.data.get("email")
    password = request.data.get("password")

    if not email or not password:
        return Response(
            {"error": "Please provide email and password"},
            status=status.HTTP_400_BAD_REQUEST,
        )

    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        return Response(
            {"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED
        )

    user = authenticate(username=user.username, password=password)
    if user is not None:
        custom_user, created = CustomUser.objects.get_or_create(user=user)
        role = (
            "superadmin"
            if custom_user.is_superadmin
            else "admin" if custom_user.is_admin else "user"
        )
        refresh = RefreshToken.for_user(user)
        return Response(
            {
                "refresh": str(refresh),
                "access": str(refresh.access_token),
                "msg": "Login successful",
                "role": role,
            }
        )
    else:
        return Response(
            {"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED
        )


# List all users (requires authentication)
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def user_list(request):
    users = User.objects.all()
    data = [
        {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": (
                "superadmin"
                if hasattr(user, "customuser") and user.customuser.is_superadmin
                else (
                    "admin"
                    if hasattr(user, "customuser") and user.customuser.is_admin
                    else "user"
                )
            ),
            "is_staff": user.is_staff,
            "is_active": user.is_active,
        }
        for user in users
    ]
    return Response(data)


# Update user role based on JSON data
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def update_user_role(request):
    logger.info(f"Received data: {request.data}")

    user_id = request.data.get("id")
    role = request.data.get("role")

    if not user_id or not role:
        return Response(
            {"error": "Please provide both id and role"},
            status=status.HTTP_400_BAD_REQUEST,
        )

    try:
        user_to_update = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

    authenticated_user = request.user
    custom_user_auth = CustomUser.objects.get(user=authenticated_user)
    current_role = (
        "superadmin"
        if custom_user_auth.is_superadmin
        else "admin" if custom_user_auth.is_admin else "user"
    )

    custom_user_to_update = CustomUser.objects.get(user=user_to_update)
    current_role_to_update = (
        "superadmin"
        if custom_user_to_update.is_superadmin
        else "admin" if custom_user_to_update.is_admin else "user"
    )

    if current_role == "user":
        return Response(
            {"error": "Users cannot update roles"}, status=status.HTTP_403_FORBIDDEN
        )

    elif current_role == "admin":
        if role.lower() == "superadmin":
            return Response(
                {"error": "Admins cannot assign superadmin role"},
                status=status.HTTP_403_FORBIDDEN,
            )
        if current_role_to_update == "superadmin":
            return Response(
                {"error": "Admins cannot modify a superadmin role"},
                status=status.HTTP_403_FORBIDDEN,
            )
        if role.lower() not in ["admin", "user"] or (
            current_role_to_update not in ["user", "admin"]
        ):
            return Response(
                {"error": "Admins can only change user to admin, or admin to user"},
                status=status.HTTP_403_FORBIDDEN,
            )

    # Role update logic
    if role.lower() == "superadmin":
        custom_user_to_update.is_superadmin = True
        custom_user_to_update.is_admin = False
        custom_user_to_update.is_user = False
        user_to_update.is_staff = True
        user_to_update.is_superuser = True

    elif role.lower() == "admin":
        custom_user_to_update.is_superadmin = False
        custom_user_to_update.is_admin = True
        custom_user_to_update.is_user = False
        user_to_update.is_staff = True
        user_to_update.is_superuser = False

    elif role.lower() == "user":
        custom_user_to_update.is_superadmin = False
        custom_user_to_update.is_admin = False
        custom_user_to_update.is_user = True
        user_to_update.is_staff = True
        user_to_update.is_superuser = False

    else:
        return Response(
            {"error": "Invalid role. Use superadmin, admin, or user"},
            status=status.HTTP_400_BAD_REQUEST,
        )

    # Save both user and role info
    custom_user_to_update.save()
    user_to_update.save()

    return Response(
        {"msg": f"User {user_to_update.username} role updated to {role}", "role": role},
        status=status.HTTP_200_OK,
    )


# Change Password
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def change_password(request):
    serializer = ChangePasswordSerializer(data=request.data)

    if serializer.is_valid():
        user = request.user
        old_password = serializer.validated_data["old_password"]
        new_password = serializer.validated_data["new_password"]

        if not user.check_password(old_password):
            return Response(
                {"error": "Old password is incorrect"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user.set_password(new_password)
        user.save()

        return Response(
            {"msg": "Password changed successfully"}, status=status.HTTP_200_OK
        )

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# Forgot Password
@api_view(["POST"])
@permission_classes([AllowAny])
def forgot_password(request):
    serializer = ForgotPasswordSerializer(data=request.data)
    if serializer.is_valid():
        email = serializer.validated_data["email"]
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response(
                {"error": "User with this email does not exist"},
                status=status.HTTP_404_NOT_FOUND,
            )

        # Generate 6-digit OTP
        otp = str(random.randint(100000, 999999))
        cache.set(f"otp_{email}", otp, timeout=600)  # 10 minutes

        # Send OTP via email
        send_mail(
            subject="Password Reset OTP",
            message=(
                f"We received a request to reset your password.\n"
                f"Please use the following One-Time Password (OTP) to proceed:\n\n"
                f"👉  {otp}\n\n"
                f"⚠️ This OTP is valid for only 10 minutes.\n\n"
                f"Thank you,\n"
                f"Utility Management System Team"
            ),
            from_email="sabbir@scube.com.bd",  # Update this if needed
            recipient_list=[email],
            fail_silently=False,
        )

        return Response({"msg": "OTP sent to your email"}, status=status.HTTP_200_OK)

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# Reset Password
@api_view(["POST"])
@permission_classes([AllowAny])
def reset_password(request):
    serializer = ResetPasswordSerializer(data=request.data)
    if serializer.is_valid():
        email = serializer.validated_data["email"]
        otp = serializer.validated_data["otp"]
        new_password = serializer.validated_data["new_password"]

        saved_otp = cache.get(f"otp_{email}")
        if saved_otp != otp:
            return Response(
                {"error": "Invalid or expired OTP"}, status=status.HTTP_400_BAD_REQUEST
            )

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response(
                {"error": "User not found"}, status=status.HTTP_404_NOT_FOUND
            )

        user.set_password(new_password)
        user.save()
        cache.delete(f"otp_{email}")  # remove used OTP

        return Response(
            {"msg": "Password reset successfully"}, status=status.HTTP_200_OK
        )

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# Logout
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout_user(request):
    try:
        refresh_token = request.data.get("refresh")
        token = RefreshToken(refresh_token)
        token.blacklist()
        return Response({"msg": "Logout successful"}, status=status.HTTP_205_RESET_CONTENT)
    except Exception as e:
        return Response({"error": "Invalid or missing refresh token"}, status=status.HTTP_400_BAD_REQUEST)