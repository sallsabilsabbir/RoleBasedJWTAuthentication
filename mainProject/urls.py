
from django.contrib import admin
from django.urls import path,include
from authenticationApis import views

urlpatterns = [
    path('admin/', admin.site.urls), # Admin panel
    path('api-auth/', include('rest_framework.urls', namespace='rest_framework')), # REST framework login


    path('api/register/', views.register_user, name='register'),
    path('api/login/', views.login_user, name='login'),
    path('api/users/', views.user_list, name='user_list'),
]











