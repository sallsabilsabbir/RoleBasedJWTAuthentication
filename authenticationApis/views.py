from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import RegisterSerializer, LoginSerializer
from .models import CustomUser

# Register a new user
@api_view(['POST'])
@permission_classes([AllowAny])
def register_user(request):
    # Get data from request
    username = request.data.get('username')
    email = request.data.get('email')
    password = request.data.get('password')

    # Check if all fields are provided
    if not username or not email or not password:
        return Response({'error': 'Please provide username, email, and password'}, status=status.HTTP_400_BAD_REQUEST)

    # Check if username already exists
    if User.objects.filter(username=username).exists():
        return Response({'error': 'Username already exists'}, status=status.HTTP_400_BAD_REQUEST)

    # Create new user
    user = User.objects.create_user(username=username, email=email, password=password)
    refresh = RefreshToken.for_user(user)
    custom_user = CustomUser.objects.get(user=user)  # Get the linked CustomUser
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
    # Get data from request
    email = request.data.get('email')
    password = request.data.get('password')

    # Check if all fields are provided
    if not email or not password:
        return Response({'error': 'Please provide email and password'}, status=status.HTTP_400_BAD_REQUEST)

    # Get user by email
    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

    # Authenticate user
    user = authenticate(username=user.username, password=password)
    if user is not None:
        custom_user, created = CustomUser.objects.get_or_create(user=user)  # Ensure CustomUser exists
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
    # Get all users
    users = User.objects.all()
    # Prepare data with roles
    data = [{'id': user.id, 'username': user.username, 'email': user.email, 'role': 'superadmin' if hasattr(user, 'customuser') and user.customuser.is_superadmin else 'admin' if hasattr(user, 'customuser') and user.customuser.is_admin else 'user'} for user in users]
    return Response(data)