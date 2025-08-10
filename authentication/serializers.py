# authentication/serializers.py - FIXED VERSION

from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from .models import CustomUser, UserStaffAssignment, OTPCode, CustomAuthToken


class UserSerializer(serializers.ModelSerializer):
    """
    Serializer for CustomUser model
    """
    password = serializers.CharField(write_only=True, required=False)
    password_confirm = serializers.CharField(write_only=True, required=False)
    assigned_staff_count = serializers.SerializerMethodField()
    assigned_users_count = serializers.SerializerMethodField()

    class Meta:
        model = CustomUser
        fields = [
            'id', 'email', 'full_name', 'mobile_number', 'organization',
            'designation', 'user_type', 'is_active', 'created_at', 'updated_at',
            'last_login', 'password', 'password_confirm', 'assigned_staff_count',
            'assigned_users_count'
        ]
        read_only_fields = [
            'id', 'created_at', 'updated_at', 'last_login',
            'assigned_staff_count', 'assigned_users_count'
        ]
        extra_kwargs = {
            'password': {'write_only': True, 'min_length': 8},
        }

    def get_assigned_staff_count(self, obj):
        """Get count of assigned staff for regular users"""
        if obj.user_type == 'USER':
            return obj.assigned_staff.filter(is_active=True).count()
        return 0

    def get_assigned_users_count(self, obj):
        """Get count of assigned users for staff/superuser"""
        if obj.user_type in ['STAFF', 'SUPERUSER']:  # FIXED: Include superuser
            return obj.assigned_users.filter(is_active=True).count()
        return 0

    def validate_email(self, value):
        """Validate email uniqueness"""
        if self.instance:
            # For updates, exclude current instance
            if CustomUser.objects.filter(email=value).exclude(id=self.instance.id).exists():
                raise serializers.ValidationError("This email is already in use.")
        else:
            # For creation
            if CustomUser.objects.filter(email=value).exists():
                raise serializers.ValidationError("This email is already in use.")
        return value

    def validate_mobile_number(self, value):
        """Validate mobile number format"""
        # Remove spaces and special characters
        cleaned_number = ''.join(filter(str.isdigit, value))

        if len(cleaned_number) < 10:
            raise serializers.ValidationError("Mobile number must be at least 10 digits.")

        if len(cleaned_number) > 15:
            raise serializers.ValidationError("Mobile number cannot exceed 15 digits.")

        return value

    def validate(self, attrs):
        """Cross-field validation"""
        if 'password' in attrs and 'password_confirm' in attrs:
            if attrs['password'] != attrs['password_confirm']:
                raise serializers.ValidationError({
                    'password_confirm': 'Password fields do not match.'
                })

        # Validate password if provided
        if 'password' in attrs:
            try:
                validate_password(attrs['password'])
            except ValidationError as e:
                raise serializers.ValidationError({'password': e.messages})

        return attrs

    def create(self, validated_data):
        """Create new user with password hashing"""
        validated_data.pop('password_confirm', None)
        password = validated_data.pop('password', None)

        user = CustomUser(**validated_data)
        if password:
            user.set_password(password)
        user.save()

        return user

    def update(self, instance, validated_data):
        """Update user with password hashing"""
        validated_data.pop('password_confirm', None)
        password = validated_data.pop('password', None)

        for attr, value in validated_data.items():
            setattr(instance, attr, value)

        if password:
            instance.set_password(password)

        instance.save()
        return instance


class UserBasicSerializer(serializers.ModelSerializer):
    """
    Basic user serializer for nested relationships
    """

    class Meta:
        model = CustomUser
        fields = [
            'id', 'email', 'full_name', 'mobile_number',
            'organization', 'designation', 'user_type'
        ]


class UserStaffAssignmentSerializer(serializers.ModelSerializer):
    """
    Serializer for UserStaffAssignment model
    """
    staff_details = UserBasicSerializer(source='staff', read_only=True)
    user_details = UserBasicSerializer(source='user', read_only=True)
    assigned_by_details = UserBasicSerializer(source='assigned_by', read_only=True)

    class Meta:
        model = UserStaffAssignment
        fields = [
            'id', 'staff', 'user', 'assigned_by', 'assigned_at',
            'is_active', 'notes', 'staff_details', 'user_details',
            'assigned_by_details'
        ]
        read_only_fields = ['id', 'assigned_at']

    def validate(self, attrs):
        """Validate staff-user assignment"""
        staff = attrs.get('staff')
        user = attrs.get('user')

        if staff and staff.user_type not in ['STAFF', 'SUPERUSER']:
            raise serializers.ValidationError({
                'staff': 'Only users with user_type="STAFF" or "SUPERUSER" can be assigned as staff members.'
            })

        if user and user.user_type != 'USER':
            raise serializers.ValidationError({
                'user': 'Only users with user_type="USER" can be assigned to staff members.'
            })

        if staff and user and staff == user:
            raise serializers.ValidationError({
                'non_field_errors': ['User cannot be assigned to themselves.']
            })

        # Check for duplicate active assignments
        if not self.instance:  # Creating new assignment
            existing = UserStaffAssignment.objects.filter(
                staff=staff, user=user, is_active=True
            ).exists()
            if existing:
                raise serializers.ValidationError({
                    'non_field_errors': ['This staff-user assignment already exists.']
                })

        return attrs


class OTPRequestSerializer(serializers.Serializer):
    """
    Serializer for OTP request - FIXED VERSION
    """
    email = serializers.EmailField()

    def validate_email(self, value):
        """Validate that user exists and is active"""
        try:
            user = CustomUser.objects.get(email=value)
            if not user.is_active:
                raise serializers.ValidationError("User account is inactive.")
            # FIXED: Allow all user types to use OTP login
            # Superusers now have full privileges including OTP access
        except CustomUser.DoesNotExist:
            raise serializers.ValidationError("User with this email does not exist.")

        return value


class OTPVerifySerializer(serializers.Serializer):
    """
    Serializer for OTP verification
    """
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6, min_length=6)

    def validate_email(self, value):
        """Validate that user exists"""
        try:
            CustomUser.objects.get(email=value, is_active=True)
        except CustomUser.DoesNotExist:
            raise serializers.ValidationError("User not found.")
        return value

    def validate_otp(self, value):
        """Validate OTP format"""
        if not value.isdigit():
            raise serializers.ValidationError("OTP must contain only digits.")
        return value


class TokenSerializer(serializers.ModelSerializer):
    """
    Serializer for CustomAuthToken model
    """
    user_details = UserBasicSerializer(source='user', read_only=True)
    token_masked = serializers.SerializerMethodField()
    is_valid_token = serializers.SerializerMethodField()

    class Meta:
        model = CustomAuthToken
        fields = [
            'id', 'user', 'token_masked', 'created_at', 'expires_at',
            'is_active', 'last_used', 'device_info', 'user_details',
            'is_valid_token'
        ]
        read_only_fields = [
            'id', 'token', 'created_at', 'last_used', 'token_masked',
            'is_valid_token'
        ]

    def get_token_masked(self, obj):
        """Return masked token for security"""
        if len(obj.token) > 16:
            return f"{obj.token[:8]}...{obj.token[-8:]}"
        return "***"

    def get_is_valid_token(self, obj):
        """Check if token is still valid"""
        return obj.is_valid()


class OTPCodeSerializer(serializers.ModelSerializer):
    """
    Serializer for OTPCode model (read-only)
    """
    user_details = UserBasicSerializer(source='user', read_only=True)
    otp_masked = serializers.SerializerMethodField()
    is_valid_otp = serializers.SerializerMethodField()
    time_remaining = serializers.SerializerMethodField()

    class Meta:
        model = OTPCode
        fields = [
            'id', 'user', 'otp_masked', 'purpose', 'created_at',
            'expires_at', 'is_used', 'used_at', 'user_details',
            'is_valid_otp', 'time_remaining'
        ]
        read_only_fields = '__all__'

    def get_otp_masked(self, obj):
        """Return masked OTP for security"""
        if obj.is_used:
            return f"***{obj.otp_code[-2:]}"
        return "******"

    def get_is_valid_otp(self, obj):
        """Check if OTP is still valid"""
        return obj.is_valid()

    def get_time_remaining(self, obj):
        """Get remaining time in seconds"""
        if obj.is_used:
            return 0

        from django.utils import timezone
        remaining = obj.expires_at - timezone.now()
        return max(0, int(remaining.total_seconds()))


class ProfileUpdateSerializer(serializers.ModelSerializer):
    """
    Serializer for profile updates (limited fields)
    """

    class Meta:
        model = CustomUser
        fields = ['full_name', 'mobile_number', 'designation']

    def validate_mobile_number(self, value):
        """Validate mobile number format"""
        cleaned_number = ''.join(filter(str.isdigit, value))

        if len(cleaned_number) < 10:
            raise serializers.ValidationError("Mobile number must be at least 10 digits.")

        if len(cleaned_number) > 15:
            raise serializers.ValidationError("Mobile number cannot exceed 15 digits.")

        return value


class PasswordChangeSerializer(serializers.Serializer):
    """
    Serializer for password change (for admin users)
    """
    old_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True, min_length=8)
    confirm_password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        """Cross-field validation"""
        if attrs['new_password'] != attrs['confirm_password']:
            raise serializers.ValidationError({
                'confirm_password': 'Password fields do not match.'
            })

        # Validate new password
        try:
            validate_password(attrs['new_password'])
        except ValidationError as e:
            raise serializers.ValidationError({'new_password': e.messages})

        return attrs

    def validate_old_password(self, value):
        """Validate current password"""
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError("Current password is incorrect.")
        return value