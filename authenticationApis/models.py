from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver

from django.contrib.auth.models import User
from django.utils import timezone
import datetime

# CustomUser model to store user roles
class CustomUser(models.Model):
    user = models.OneToOneField(
        User, on_delete=models.CASCADE
    )  # Link to the default User
    is_superadmin = models.BooleanField(default=False)  # Superadmin role
    is_admin = models.BooleanField(default=False)  # Admin role
    is_user = models.BooleanField(default=True)  # Default user role

    def __str__(self):
        return self.user.username  # Show username as string


# Create CustomUser when a new User is saved
@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:  # Only create if it's a new user
        CustomUser.objects.create(user=instance)


# Save CustomUser when User is updated
@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    instance.customuser.save()

# OTP
class PasswordResetOTP(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_valid(self):
        return timezone.now() < self.created_at + datetime.timedelta(minutes=10)  # 10 min validity