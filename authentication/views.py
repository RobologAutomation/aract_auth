# authentication/views.py - COMPLETE VERSION WITH ALL FUNCTIONS

from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from django.contrib.auth import authenticate
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone
from django.core.cache import cache
from django.db import transaction
from django.template.loader import render_to_string
from django.utils.html import strip_tags

from .models import CustomUser, OTPCode, CustomAuthToken, UserStaffAssignment
from .serializers import UserSerializer, OTPRequestSerializer, OTPVerifySerializer
from .authentication import CustomTokenAuthentication

import logging

logger = logging.getLogger(__name__)


@api_view(['POST'])
@permission_classes([AllowAny])
def send_otp(request):
    """
    Send OTP to user or staff for login
    """
    # Debug prints
    print(f"=== DEBUG: send_otp called ===")
    print(f"Request data: {request.data}")

    serializer = OTPRequestSerializer(data=request.data)
    if not serializer.is_valid():
        print(f"Serializer errors: {serializer.errors}")
        return Response(
            {'error': 'Invalid data', 'details': serializer.errors},
            status=status.HTTP_400_BAD_REQUEST
        )

    email = serializer.validated_data['email']
    print(f"Email: {email}")

    # Rate limiting check
    cache_key = f"otp_request_{email}"
    if cache.get(cache_key):
        return Response(
            {'error': 'Please wait before requesting another OTP'},
            status=status.HTTP_429_TOO_MANY_REQUESTS
        )

    try:
        user = CustomUser.objects.get(email=email, is_active=True)
        print(f"User found: {user.email}, Type: {user.user_type}")
    except CustomUser.DoesNotExist:
        print(f"User not found: {email}")
        return Response(
            {'error': 'User not found or inactive'},
            status=status.HTTP_404_NOT_FOUND
        )

    # Invalidate any existing unused OTPs
    OTPCode.objects.filter(
        user=user,
        is_used=False,
        purpose='LOGIN'
    ).update(is_used=True)

    # Generate new OTP
    otp_code = OTPCode.generate_otp()
    print(f"Generated OTP: {otp_code}")

    otp = OTPCode.objects.create(
        user=user,
        otp_code=otp_code,
        purpose='LOGIN'
    )

    try:
        assigned_staff_info = []  # Initialize staff info list

        if user.user_type in ['STAFF', 'SUPERUSER']:
            print(f"Sending OTP to staff/superuser email: {user.email}")
            _send_staff_otp_email(user, otp_code)
            message = "OTP sent to your email address"

        elif user.user_type == 'USER':
            print(f"Sending OTP to assigned staff for user: {user.email}")
            staff_emails, assigned_staff_info = _send_user_otp_to_staff(user, otp_code)
            if not staff_emails:
                print("No staff assigned to user")
                return Response(
                    {'error': 'No staff assigned to this user. Please contact administrator.'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            message = f"OTP sent to assigned staff members"
            print(f"Staff info being returned: {assigned_staff_info}")  # Debug print

        else:
            print(f"Invalid user type: {user.user_type}")
            return Response(
                {'error': 'Invalid user type'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Set rate limiting cache
        cache.set(cache_key, True, settings.OTP_RESEND_DELAY_SECONDS)

        logger.info(f"OTP sent successfully for user: {email}")
        print(f"SUCCESS: OTP sent for {email}")

        # Prepare response data
        response_data = {
            'message': message,
            'expires_in': settings.OTP_EXPIRY_MINUTES * 60,
            'user_type': user.user_type
        }

        # Add staff info for regular users
        if user.user_type == 'USER' and assigned_staff_info:
            response_data['assigned_staff'] = assigned_staff_info
            print(f"Final response data: {response_data}")  # Debug print

        return Response(response_data, status=status.HTTP_200_OK)

    except Exception as e:
        logger.error(f"Failed to send OTP for {email}: {str(e)}")
        print(f"ERROR: {str(e)}")
        import traceback
        traceback.print_exc()
        return Response(
            {'error': 'Failed to send OTP. Please try again.'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([AllowAny])
def verify_otp(request):
    """
    Verify OTP and return authentication token
    """
    serializer = OTPVerifySerializer(data=request.data)
    if not serializer.is_valid():
        return Response(
            {'error': 'Invalid data', 'details': serializer.errors},
            status=status.HTTP_400_BAD_REQUEST
        )

    email = serializer.validated_data['email']
    otp_code = serializer.validated_data['otp']

    try:
        user = CustomUser.objects.get(email=email, is_active=True)
    except CustomUser.DoesNotExist:
        return Response(
            {'error': 'User not found'},
            status=status.HTTP_404_NOT_FOUND
        )

    # Find valid OTP
    try:
        otp = OTPCode.objects.get(
            user=user,
            otp_code=otp_code,
            purpose='LOGIN',
            is_used=False
        )
    except OTPCode.DoesNotExist:
        return Response(
            {'error': 'Invalid or expired OTP'},
            status=status.HTTP_400_BAD_REQUEST
        )

    # Check if OTP is still valid
    if not otp.is_valid():
        return Response(
            {'error': 'OTP has expired'},
            status=status.HTTP_400_BAD_REQUEST
        )

    # Mark OTP as used
    with transaction.atomic():
        otp.mark_as_used()

        # Invalidate existing tokens for this user
        CustomAuthToken.objects.filter(user=user).update(is_active=False)

        # Create new token
        auth_token = CustomAuthToken.objects.create(
            user=user,
            device_info=request.META.get('HTTP_USER_AGENT', '')
        )

    logger.info(f"Successful login for user: {email}")

    response_data = {
        'token': auth_token.token,
        'user_type': user.user_type,
        'user': UserSerializer(user).data
    }

    if auth_token.expires_at:
        response_data['expires_at'] = auth_token.expires_at.isoformat()

    return Response(response_data, status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def refresh_token(request):
    """
    Refresh authentication token for regular users
    """
    user = request.user

    if user.user_type != 'USER':
        return Response(
            {'error': 'Token refresh not available for staff users'},
            status=status.HTTP_400_BAD_REQUEST
        )

    # Get current token
    auth_header = request.META.get('HTTP_AUTHORIZATION', '')
    if not auth_header.startswith('Token '):
        return Response(
            {'error': 'Invalid authorization header'},
            status=status.HTTP_400_BAD_REQUEST
        )

    token_key = auth_header.split(' ')[1]

    try:
        current_token = CustomAuthToken.objects.get(
            token=token_key,
            user=user,
            is_active=True
        )
    except CustomAuthToken.DoesNotExist:
        return Response(
            {'error': 'Invalid token'},
            status=status.HTTP_401_UNAUTHORIZED
        )

    # Refresh the token
    current_token.refresh()

    return Response({
        'token': current_token.token,
        'expires_at': current_token.expires_at.isoformat(),
        'message': 'Token refreshed successfully'
    }, status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout(request):
    """
    Logout user by invalidating token
    """
    # Get current token and invalidate it
    auth_header = request.META.get('HTTP_AUTHORIZATION', '')
    if auth_header.startswith('Token '):
        token_key = auth_header.split(' ')[1]
        CustomAuthToken.objects.filter(
            token=token_key,
            user=request.user
        ).update(is_active=False)

    logger.info(f"User logged out: {request.user.email}")

    return Response({
        'message': 'Logged out successfully'
    }, status=status.HTTP_200_OK)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_profile(request):
    """
    Get user profile information
    """
    serializer = UserSerializer(request.user)
    return Response(serializer.data, status=status.HTTP_200_OK)


@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def update_profile(request):
    """
    Update user profile information (limited fields)
    """
    user = request.user

    # Only allow updating certain fields
    allowed_fields = ['full_name', 'mobile_number', 'designation']
    update_data = {k: v for k, v in request.data.items() if k in allowed_fields}

    serializer = UserSerializer(user, data=update_data, partial=True)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)

    return Response(
        {'error': 'Invalid data', 'details': serializer.errors},
        status=status.HTTP_400_BAD_REQUEST
    )


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_assigned_users(request):
    """
    Get list of users assigned to staff member (including superusers)
    """
    if request.user.user_type not in ['STAFF', 'SUPERUSER']:
        return Response(
            {'error': 'Only staff members and superusers can access this endpoint'},
            status=status.HTTP_403_FORBIDDEN
        )

    assignments = UserStaffAssignment.objects.filter(
        staff=request.user,
        is_active=True
    ).select_related('user')

    users = [assignment.user for assignment in assignments]
    serializer = UserSerializer(users, many=True)

    return Response({
        'assigned_users': serializer.data,
        'count': len(users)
    }, status=status.HTTP_200_OK)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_recent_otp_requests(request):
    """
    Get recent OTP requests for staff members (including superusers)
    """
    if request.user.user_type not in ['STAFF', 'SUPERUSER']:
        return Response(
            {'error': 'Only staff members and superusers can access this endpoint'},
            status=status.HTTP_403_FORBIDDEN
        )

    # Get assigned users
    assigned_user_ids = UserStaffAssignment.objects.filter(
        staff=request.user,
        is_active=True
    ).values_list('user_id', flat=True)

    # Get recent OTP requests from assigned users
    recent_otps = OTPCode.objects.filter(
        user_id__in=assigned_user_ids,
        purpose='LOGIN',
        created_at__gte=timezone.now() - timezone.timedelta(hours=24)
    ).select_related('user').order_by('-created_at')[:10]

    otp_data = []
    for otp in recent_otps:
        otp_data.append({
            'user': UserSerializer(otp.user).data,
            'created_at': otp.created_at,
            'expires_at': otp.expires_at,
            'is_used': otp.is_used,
            'is_valid': otp.is_valid()
        })

    return Response({
        'recent_requests': otp_data,
        'count': len(otp_data)
    }, status=status.HTTP_200_OK)


# Helper functions for email sending

def _send_staff_otp_email(user, otp_code):
    """
    Send OTP email to staff member - SIMPLIFIED VERSION
    """
    print(f"Sending OTP email to: {user.email}")

    subject = f'Your Login OTP - {getattr(settings, "COMPANY_NAME", "Your Company")}'

    # Simple text message (no HTML template required)
    message = f"""
Dear {user.full_name},

Your login OTP: {otp_code}

This OTP is valid for {settings.OTP_EXPIRY_MINUTES} minutes only.
Please do not share this code with anyone.

If you did not request this OTP, please contact your administrator immediately.

Best regards,
{getattr(settings, 'COMPANY_NAME', 'Your Company')} Team
"""

    try:
        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            fail_silently=False
        )
        print(f"Email sent successfully to {user.email}")
    except Exception as e:
        print(f"Error sending email: {str(e)}")
        raise


def _send_user_otp_to_staff(user, otp_code):
    """
    Send user login request with OTP to all assigned staff - RETURNS STAFF INFO
    """
    print(f"Sending user OTP request to staff for: {user.email}")

    # Get all assigned staff
    staff_assignments = UserStaffAssignment.objects.filter(
        user=user,
        is_active=True
    ).select_related('staff')

    if not staff_assignments.exists():
        print("No staff assignments found")
        return [], []

    staff_emails = []
    assigned_staff_info = []

    for assignment in staff_assignments:
        staff = assignment.staff
        staff_emails.append(staff.email)

        # Prepare staff info for frontend
        staff_info = {
            'id': staff.id,
            'full_name': staff.full_name,
            'email': staff.email,
            'mobile_number': staff.mobile_number,
            'designation': staff.designation,
            'user_type': staff.user_type
        }
        assigned_staff_info.append(staff_info)

    print(f"Staff emails: {staff_emails}")
    print(f"Staff info prepared: {assigned_staff_info}")  # Debug print

    subject = f'User Login Request - OTP Required'

    # Simple text message (no HTML template required)
    message = f"""
    Dear Staff Member,
    
    A user is requesting login access. Please share the OTP below with them:
    
    USER DETAILS:
    - Name: {user.full_name}
    - Email: {user.email}
    - Mobile: {user.mobile_number}
    - Company: {user.organization}
    - Designation: {user.designation}
    
    LOGIN OTP: {otp_code}
    Valid for: {settings.OTP_EXPIRY_MINUTES} minutes
    
    INSTRUCTIONS:
    1. Please share this OTP with the user via email or secure communication
    2. Do not share this OTP with anyone other than the requesting user
    3. If you believe this request is unauthorized, contact the administrator immediately
    
    Best regards,
    {getattr(settings, 'ARACT', 'ARACT')} Security Team
    """

    try:
        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=staff_emails,
            fail_silently=False
        )
        print(f"Email sent successfully to staff: {staff_emails}")
    except Exception as e:
        print(f"Error sending email to staff: {str(e)}")
        raise

    return staff_emails, assigned_staff_info