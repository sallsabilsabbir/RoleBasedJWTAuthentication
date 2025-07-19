from rest_framework import serializers
from django.contrib.auth.models import User

# Serializer for registering a new user
class RegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = User  # Use the default User model
        fields = ('username', 'email', 'password')  # Fields to include
        extra_kwargs = {'password': {'write_only': True}}  # Password is write-only

    def create(self, validated_data):
        # Create a new user with explicit fields
        username = validated_data['username']
        email = validated_data['email']
        password = validated_data['password']
        user = User.objects.create_user(username=username, email=email, password=password)
        return user

# Serializer for login
class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()  # Email field
    password = serializers.CharField(style={'input_type': 'password'})  # Password field