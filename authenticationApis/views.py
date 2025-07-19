from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import RegisterSerializer, LoginSerializer
from .models import CustomUser
import logging

# Set up logging
logger = logging.getLogger(__name__)

# Register a new user
@api_view(['POST'])
@permission_classes([AllowAny])
def register_user(request):
    username = request.data.get('username')
    email = request.data.get('email')
    password = request.data.get('password')

    if not username or not email or not password:
        return Response({'error': 'Please provide username, email, and password'}, status=status.HTTP_400_BAD_REQUEST)

    if User.objects.filter(username=username).exists():
        return Response({'error': 'Username already exists'}, status=status.HTTP_400_BAD_REQUEST)

    user = User.objects.create_user(username=username, email=email, password=password)
    refresh = RefreshToken.for_user(user)
    custom_user = CustomUser.objects.get(user=user)
    role = 'superadmin' if custom_user.is_superadmin else 'admin' if custom_user.is_admin else 'user'
    return Response({
        'refresh': str(refresh),
        'access': str(refresh.access_token),
        'msg': 'User registered successfully',
        'role': role
    }, status=status.HTTP_201_CREATED)

# Login a user
@api_view(['POST'])
@permission_classes([AllowAny])
def login_user(request):
    email = request.data.get('email')
    password = request.data.get('password')

    if not email or not password:
        return Response({'error': 'Please provide email and password'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

    user = authenticate(username=user.username, password=password)
    if user is not None:
        custom_user, created = CustomUser.objects.get_or_create(user=user)
        role = 'superadmin' if custom_user.is_superadmin else 'admin' if custom_user.is_admin else 'user'
        refresh = RefreshToken.for_user(user)
        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'msg': 'Login successful',
            'role': role
        })
    else:
        return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

# List all users (requires authentication)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def user_list(request):
    users = User.objects.all()
    data = [{'id': user.id, 'username': user.username, 'email': user.email, 'role': 'superadmin' if hasattr(user, 'customuser') and user.customuser.is_superadmin else 'admin' if hasattr(user, 'customuser') and user.customuser.is_admin else 'user'} for user in users]
    return Response(data)

# Update user role based on JSON data
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def update_user_role(request):
    # Log the received data for debugging
    logger.info(f"Received data: {request.data}")

    # Get data from JSON body
    user_id = request.data.get('id')
    role = request.data.get('role')

    # Check if ID and role are provided
    if not user_id or not role:
        return Response({'error': 'Please provide both id and role'}, status=status.HTTP_400_BAD_REQUEST)

    # Try to get the user by ID
    try:
        user_to_update = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

    # Get the authenticated user and their role
    authenticated_user = request.user
    custom_user_auth = CustomUser.objects.get(user=authenticated_user)
    current_role = 'superadmin' if custom_user_auth.is_superadmin else 'admin' if custom_user_auth.is_admin else 'user'

    # Get the CustomUser instance for the user to update
    custom_user_to_update = CustomUser.objects.get(user=user_to_update)
    current_role_to_update = 'superadmin' if custom_user_to_update.is_superadmin else 'admin' if custom_user_to_update.is_admin else 'user'

    # Role-based permission checks
    if current_role == 'user':
        return Response({'error': 'Users cannot update roles'}, status=status.HTTP_403_FORBIDDEN)
    elif current_role == 'admin':
        if role.lower() == 'superadmin':
            return Response({'error': 'Admins cannot assign superadmin role'}, status=status.HTTP_403_FORBIDDEN)
        if current_role_to_update == 'superadmin':
            return Response({'error': 'Admins cannot modify a superadmin role'}, status=status.HTTP_403_FORBIDDEN)
        if role.lower() not in ['admin', 'user'] or (current_role_to_update not in ['user', 'admin']):
            return Response({'error': 'Admins can only change user to admin, or admin to user'}, status=status.HTTP_403_FORBIDDEN)
    # Superadmin can do everything (no restriction)

    # Update role based on the provided role parameter
    if role.lower() == 'superadmin':
        custom_user_to_update.is_superadmin = True
        custom_user_to_update.is_admin = False
        custom_user_to_update.is_user = False
    elif role.lower() == 'admin':
        custom_user_to_update.is_superadmin = False
        custom_user_to_update.is_admin = True
        custom_user_to_update.is_user = False
    elif role.lower() == 'user':
        custom_user_to_update.is_superadmin = False
        custom_user_to_update.is_admin = False
        custom_user_to_update.is_user = True
    else:
        return Response({'error': 'Invalid role. Use superadmin, admin, or user'}, status=status.HTTP_400_BAD_REQUEST)

    # Save the changes
    custom_user_to_update.save()
    return Response({'msg': f'User {user_to_update.username} role updated to {role}', 'role': role}, status=status.HTTP_200_OK)