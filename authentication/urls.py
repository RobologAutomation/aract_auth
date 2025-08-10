# authentication/urls.py

from django.urls import path
from . import views

app_name = 'authentication'

urlpatterns = [
    # Authentication endpoints
    path('api/auth/send-otp/', views.send_otp, name='send_otp'),
    path('api/auth/verify-otp/', views.verify_otp, name='verify_otp'),
    path('api/auth/refresh-token/', views.refresh_token, name='refresh_token'),
    path('api/auth/logout/', views.logout, name='logout'),

    # User profile endpoints
    path('api/user/profile/', views.get_profile, name='get_profile'),
    path('api/user/profile/update/', views.update_profile, name='update_profile'),

    # Staff specific endpoints
    path('api/staff/assigned-users/', views.get_assigned_users, name='get_assigned_users'),
    path('api/staff/otp-requests/', views.get_recent_otp_requests, name='get_recent_otp_requests'),
]