from django.contrib import admin
from django.urls import path, include
from authenticationApis import views

urlpatterns = [
    path("admin/", admin.site.urls),  # Admin panel
    path( "api-auth/", include("rest_framework.urls", namespace="rest_framework")),  # REST framework login

    path("api/register/", views.register_user, name="register"),  # api/register/?with_role=devtr for set role
    path("api/login/", views.login_user, name="login"),
    path("api/update-role/", views.update_user_role, name="update_role"),
    path("api/change-password/", views.change_password, name="change_password"),
    path("api/forgot-password/", views.forgot_password, name="forgot_password"),
    path("api/reset-password/", views.reset_password, name="reset_password"),
    path("api/logout/", views.logout_user, name="logout_user"),

    path("api/users/", views.user_list, name="user_list"),
]
