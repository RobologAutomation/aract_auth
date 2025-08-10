from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.db import models
from django.utils import timezone
from datetime import timedelta
import secrets
import string


class CustomUserManager(BaseUserManager):
    """
    Custom user manager for CustomUser model
    """

    def create_user(self, email, full_name, mobile_number, organization, designation, password=None, **extra_fields):
        """
        Create and return a regular user with an email and password.
        """
        if not email:
            raise ValueError('The Email field must be set')
        if not full_name:
            raise ValueError('The Full Name field must be set')
        if not mobile_number:
            raise ValueError('The Mobile Number field must be set')
        if not organization:
            raise ValueError('The Organization field must be set')
        if not designation:
            raise ValueError('The Designation field must be set')

        email = self.normalize_email(email)
        extra_fields.setdefault('is_active', False)
        extra_fields.setdefault('user_type', 'USER')

        user = self.model(
            email=email,
            full_name=full_name,
            mobile_number=mobile_number,
            organization=organization,
            designation=designation,
            **extra_fields
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, full_name, mobile_number, organization, designation, password=None,
                         **extra_fields):
        """
        Create and return a superuser with an email and password.
        """
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        extra_fields.setdefault('user_type', 'SUPERUSER')

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self.create_user(email, full_name, mobile_number, organization, designation, password, **extra_fields)


class CustomUser(AbstractUser):
    """
    Custom User Model extending Django's AbstractUser
    """
    USER_TYPE_CHOICES = [
        ('SUPERUSER', 'Super User'),
        ('STAFF', 'Staff'),
        ('USER', 'Regular User'),
    ]

    # Override username to use email
    username = None
    email = models.EmailField(unique=True, verbose_name='Email Address')

    # Required fields
    full_name = models.CharField(max_length=100, verbose_name='Full Name')
    mobile_number = models.CharField(max_length=15, verbose_name='Mobile Number')
    organization = models.CharField(max_length=100, verbose_name='Organization')
    designation = models.CharField(max_length=100, verbose_name='Designation')

    # User type classification
    user_type = models.CharField(
        max_length=10,
        choices=USER_TYPE_CHOICES,
        default='USER',
        verbose_name='User Type'
    )

    # Account status
    is_active = models.BooleanField(default=False, verbose_name='Active Status')

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # Set email as the username field
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['full_name', 'mobile_number', 'organization', 'designation']

    # Use the custom manager
    objects = CustomUserManager()

    class Meta:
        verbose_name = 'User'
        verbose_name_plural = 'Users'
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.full_name} ({self.email})"

    def save(self, *args, **kwargs):
        # Auto-set user permissions based on user_type
        if self.user_type == 'SUPERUSER':
            self.is_staff = True
            self.is_superuser = True
            self.is_active = True
        elif self.user_type == 'STAFF':
            self.is_staff = False
            self.is_superuser = False
        else:  # Regular USER
            self.is_staff = False
            self.is_superuser = False

        super().save(*args, **kwargs)


class UserStaffAssignment(models.Model):
    """
    Model to handle Many-to-Many relationship between Staff and Regular Users
    """
    staff = models.ForeignKey(
        CustomUser,
        on_delete=models.CASCADE,
        related_name='assigned_users',
        limit_choices_to={'user_type__in': ['STAFF', 'SUPERUSER']},  # Allow both STAFF and SUPERUSER
        verbose_name='Staff Member'
    )
    user = models.ForeignKey(
        CustomUser,
        on_delete=models.CASCADE,
        related_name='assigned_staff',
        limit_choices_to={'user_type': 'USER'},
        verbose_name='Regular User'
    )
    assigned_by = models.ForeignKey(
        CustomUser,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='assignments_made',
        limit_choices_to={'user_type': 'SUPERUSER'},
        verbose_name='Assigned By'
    )
    assigned_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True, verbose_name='Assignment Active')
    notes = models.TextField(blank=True, null=True, verbose_name='Assignment Notes')

    class Meta:
        verbose_name = 'Staff-User Assignment'
        verbose_name_plural = 'Staff-User Assignments'
        unique_together = ['staff', 'user']  # Prevent duplicate assignments
        ordering = ['-assigned_at']

    def __str__(self):
        return f"{self.staff.full_name} -> {self.user.full_name}"

    def clean(self):
        from django.core.exceptions import ValidationError

        # Validate that staff is either STAFF or SUPERUSER
        if self.staff.user_type not in ['STAFF', 'SUPERUSER']:
            raise ValidationError('Only users with user_type="STAFF" or "SUPERUSER" can be assigned as staff members.')

        # Validate that user is actually a regular user
        if self.user.user_type != 'USER':
            raise ValidationError('Only users with user_type="USER" can be assigned to staff members.')

        # Prevent self-assignment (user cannot be assigned to themselves)
        if self.staff == self.user:
            raise ValidationError('User cannot be assigned to themselves')


class OTPCode(models.Model):
    """
    Model to store and manage OTP codes
    """
    PURPOSE_CHOICES = [
        ('LOGIN', 'Login'),
        ('ACTIVATION', 'Account Activation'),
        ('PASSWORD_RESET', 'Password Reset'),
    ]

    user = models.ForeignKey(
        CustomUser,
        on_delete=models.CASCADE,
        related_name='otp_codes',
        verbose_name='User'
    )
    otp_code = models.CharField(max_length=6, verbose_name='OTP Code')
    purpose = models.CharField(
        max_length=15,
        choices=PURPOSE_CHOICES,
        default='LOGIN',
        verbose_name='Purpose'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(verbose_name='Expires At')
    is_used = models.BooleanField(default=False, verbose_name='Used Status')
    used_at = models.DateTimeField(null=True, blank=True, verbose_name='Used At')

    class Meta:
        verbose_name = 'OTP Code'
        verbose_name_plural = 'OTP Codes'
        ordering = ['-created_at']

    def __str__(self):
        return f"OTP for {self.user.email} - {self.otp_code}"

    def save(self, *args, **kwargs):
        if not self.expires_at:
            # Set expiry to 10 minutes from creation
            self.expires_at = timezone.now() + timedelta(minutes=10)
        super().save(*args, **kwargs)

    @classmethod
    def generate_otp(cls):
        """Generate a 6-digit OTP code"""
        return ''.join(secrets.choice(string.digits) for _ in range(6))

    def is_valid(self):
        """Check if OTP is still valid"""
        return not self.is_used and timezone.now() < self.expires_at

    def mark_as_used(self):
        """Mark OTP as used"""
        self.is_used = True
        self.used_at = timezone.now()
        self.save(update_fields=['is_used', 'used_at'])


class CustomAuthToken(models.Model):
    """
    Custom Token Model for API Authentication
    """
    user = models.ForeignKey(
        CustomUser,
        on_delete=models.CASCADE,
        related_name='auth_tokens',
        verbose_name='User'
    )
    token = models.CharField(max_length=255, unique=True, verbose_name='Token')
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name='Expires At',
        help_text='NULL for staff tokens (no expiry)'
    )
    is_active = models.BooleanField(default=True, verbose_name='Active Status')
    last_used = models.DateTimeField(null=True, blank=True, verbose_name='Last Used')
    device_info = models.TextField(blank=True, null=True, verbose_name='Device Information')

    class Meta:
        verbose_name = 'Authentication Token'
        verbose_name_plural = 'Authentication Tokens'
        ordering = ['-created_at']

    def __str__(self):
        return f"Token for {self.user.email}"

    def save(self, *args, **kwargs):
        if not self.token:
            self.token = self.generate_token()

        # Set expiry based on user type
        if not self.expires_at and self.user.user_type == 'USER':
            # Regular users get 7-day expiry
            self.expires_at = timezone.now() + timedelta(days=7)
        # Staff tokens have no expiry (expires_at remains NULL)

        super().save(*args, **kwargs)

    @staticmethod
    def generate_token():
        """Generate a secure random token"""
        return secrets.token_urlsafe(32)

    def is_valid(self):
        """Check if token is still valid"""
        if not self.is_active:
            return False

        if self.expires_at and timezone.now() > self.expires_at:
            return False

        return True

    def refresh(self):
        """Refresh token expiry for regular users"""
        if self.user.user_type == 'USER':
            self.expires_at = timezone.now() + timedelta(days=7)
            self.save(update_fields=['expires_at'])

    def update_last_used(self):
        """Update last used timestamp"""
        self.last_used = timezone.now()
        self.save(update_fields=['last_used'])