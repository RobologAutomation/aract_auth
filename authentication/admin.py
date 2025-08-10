# authentication/admin.py - ARACT BATT PULSE Branded Admin

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.utils.html import format_html
from django.urls import reverse
from django.conf import settings
from django.db import models
from .models import CustomUser, UserStaffAssignment, OTPCode, CustomAuthToken
from django.contrib.admin import site

# Add custom CSS to admin
site.add_css_class = """
<style>
#header { background: #90EE90 !important; background: linear-gradient(135deg, #90EE90 0%, #32CD32 100%) !important; }
</style>
"""

@admin.register(CustomUser)
class CustomUserAdmin(UserAdmin):
    """Enhanced Custom User Admin with ARACT Branding"""

    list_display = [
        'email', 'full_name', 'user_type_badge', 'organization',
        'designation', 'status_badge', 'created_at', 'assigned_staff_count'
    ]
    list_filter = [
        'user_type', 'is_active', 'organization', 'created_at',
        'is_staff', 'is_superuser'
    ]
    search_fields = ['email', 'full_name', 'mobile_number', 'organization']
    ordering = ['-created_at']
    readonly_fields = ['created_at', 'updated_at', 'last_login', 'date_joined']
    list_per_page = 25

    fieldsets = (
        ('🔐 Authentication', {
            'fields': ('email', 'password'),
            'classes': ('wide',)
        }),
        ('👤 Personal Information', {
            'fields': ('full_name', 'mobile_number', 'organization', 'designation'),
            'classes': ('wide',)
        }),
        ('⚡ User Type & Permissions', {
            'fields': ('user_type', 'is_active', 'is_staff', 'is_superuser'),
            'classes': ('wide',)
        }),
        ('📅 Timestamps', {
            'fields': ('created_at', 'updated_at', 'last_login', 'date_joined'),
            'classes': ('collapse', 'wide')
        })
    )

    add_fieldsets = (
        ('✨ Create New User', {
            'classes': ('wide',),
            'fields': ('email', 'full_name', 'mobile_number', 'organization',
                       'designation', 'user_type', 'password1', 'password2', 'is_active'),
            'description': 'Create a new user account with the required information.'
        }),
    )

    username = None

    def assigned_staff_count(self, obj):
        """Enhanced staff count display with light green theme"""
        if obj.user_type == 'USER':
            count = obj.assigned_staff.filter(is_active=True).count()
            if count > 0:
                url = reverse('admin:authentication_userstaffassignment_changelist')
                return format_html(
                    '<a href="{}?user__id__exact={}" style="background: #90EE90; color: #2d5a2d; '
                    'padding: 4px 8px; border-radius: 12px; text-decoration: none; font-size: 11px; font-weight: bold; '
                    'box-shadow: 0 2px 4px rgba(144, 238, 144, 0.3);">'
                    '👥 {} Staff</a>',
                    url, obj.id, count
                )
            else:
                return format_html(
                    '<span style="background: #FFB6C1; color: #8B0000; padding: 4px 8px; '
                    'border-radius: 12px; font-size: 11px; font-weight: bold; '
                    'box-shadow: 0 2px 4px rgba(255, 182, 193, 0.3);">⚠️ No Staff</span>'
                )
        return format_html('<span style="color: #6c757d;">—</span>')

    assigned_staff_count.short_description = '👥 Assigned Staff'

    def user_type_badge(self, obj):
        """Enhanced user type badge with light green theme"""
        badges = {
            'SUPERUSER': ('👑 Super Admin', '#32CD32'),  # Lime Green
            'STAFF': ('👨‍💼 Staff', '#90EE90'),  # Light Green
            'USER': ('👤 User', '#98FB98')  # Pale Green
        }
        label, color = badges.get(obj.user_type, ('Unknown', '#6c757d'))
        return format_html(
            '<span style="background: {}; color: #2d5a2d; padding: 4px 8px; '
            'border-radius: 12px; font-size: 11px; font-weight: bold; '
            'box-shadow: 0 2px 4px rgba(144, 238, 144, 0.3);">{}</span>',
            color, label
        )

    user_type_badge.short_description = '🏷️ User Type'
    user_type_badge.admin_order_field = 'user_type'

    def status_badge(self, obj):
        """Enhanced status badge with light green theme"""
        if obj.is_active:
            return format_html(
                '<span style="background: #90EE90; color: #2d5a2d; padding: 4px 8px; '
                'border-radius: 12px; font-size: 11px; font-weight: bold; '
                'box-shadow: 0 2px 4px rgba(144, 238, 144, 0.3);">✅ Active</span>'
            )
        else:
            return format_html(
                '<span style="background: #D3D3D3; color: #696969; padding: 4px 8px; '
                'border-radius: 12px; font-size: 11px; font-weight: bold; '
                'box-shadow: 0 2px 4px rgba(211, 211, 211, 0.3);">❌ Inactive</span>'
            )

    status_badge.short_description = '🔄 Status'
    status_badge.admin_order_field = 'is_active'

    def get_queryset(self, request):
        """Optimize queries"""
        qs = super().get_queryset(request)
        return qs.prefetch_related('assigned_staff')

    actions = ['activate_users', 'deactivate_users', 'export_users']

    def activate_users(self, request, queryset):
        """Bulk activate users"""
        updated = queryset.update(is_active=True)
        self.message_user(
            request,
            f'✅ {updated} user(s) were successfully activated.',
            level='SUCCESS'
        )

    activate_users.short_description = "✅ Activate selected users"

    def deactivate_users(self, request, queryset):
        """Bulk deactivate users"""
        updated = queryset.update(is_active=False)
        self.message_user(
            request,
            f'❌ {updated} user(s) were successfully deactivated.',
            level='WARNING'
        )

    deactivate_users.short_description = "❌ Deactivate selected users"

    def export_users(self, request, queryset):
        """Export users to CSV"""
        import csv
        from django.http import HttpResponse
        from datetime import datetime

        response = HttpResponse(content_type='text/csv')
        response[
            'Content-Disposition'] = f'attachment; filename="aract_users_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv"'

        writer = csv.writer(response)
        writer.writerow(
            ['Email', 'Full Name', 'User Type', 'Organization', 'Designation', 'Mobile', 'Status', 'Created'])

        for user in queryset:
            writer.writerow([
                user.email, user.full_name, user.get_user_type_display(),
                user.organization, user.designation, user.mobile_number,
                'Active' if user.is_active else 'Inactive', user.created_at.strftime('%Y-%m-%d')
            ])

        self.message_user(request, f'📊 Exported {queryset.count()} users to CSV.')
        return response

    export_users.short_description = "📊 Export selected users to CSV"


@admin.register(UserStaffAssignment)
class UserStaffAssignmentAdmin(admin.ModelAdmin):
    """Enhanced Staff Assignment Admin with ARACT Branding"""

    list_display = [
        'user_info', 'staff_info', 'assignment_status',
        'assigned_by_info', 'assigned_at'
    ]
    list_filter = [
        'is_active', 'assigned_at', 'staff__organization', 'user__organization'
    ]
    search_fields = [
        'user__email', 'user__full_name', 'staff__email', 'staff__full_name'
    ]
    autocomplete_fields = ['user', 'staff', 'assigned_by']
    readonly_fields = ['assigned_at']
    ordering = ['-assigned_at']
    list_per_page = 20

    fieldsets = (
        ('👥 Assignment Details', {
            'fields': ('staff', 'user', 'assigned_by', 'is_active'),
            'classes': ('wide',)
        }),
        ('📝 Additional Information', {
            'fields': ('notes', 'assigned_at'),
            'classes': ('collapse', 'wide')
        })
    )

    def user_info(self, obj):
        """Enhanced user info display"""
        return format_html(
            '<div><strong>👤 {}</strong><br><small style="color: #6c757d;">📧 {}</small></div>',
            obj.user.full_name, obj.user.email
        )

    user_info.short_description = '👤 User'
    user_info.admin_order_field = 'user__full_name'

    def staff_info(self, obj):
        """Enhanced staff info display with light green theme"""
        color = '#32CD32' if obj.staff.user_type == 'SUPERUSER' else '#90EE90'
        icon = '👑' if obj.staff.user_type == 'SUPERUSER' else '👨‍💼'
        return format_html(
            '<div><strong>{} {}</strong><br><small style="color: #6c757d;">📧 {}</small><br>'
            '<span style="background: {}; color: #2d5a2d; padding: 2px 6px; border-radius: 8px; '
            'font-size: 10px; font-weight: bold; box-shadow: 0 1px 3px rgba(144, 238, 144, 0.3);">{}</span></div>',
            icon, obj.staff.full_name, obj.staff.email,
            color, obj.staff.get_user_type_display()
        )

    staff_info.short_description = '👨‍💼 Staff Member'
    staff_info.admin_order_field = 'staff__full_name'

    def assignment_status(self, obj):
        """Enhanced assignment status with light green theme"""
        if obj.is_active:
            return format_html(
                '<span style="background: #90EE90; color: #2d5a2d; padding: 4px 8px; '
                'border-radius: 12px; font-size: 11px; font-weight: bold; '
                'box-shadow: 0 2px 4px rgba(144, 238, 144, 0.3);">✅ Active</span>'
            )
        else:
            return format_html(
                '<span style="background: #D3D3D3; color: #696969; padding: 4px 8px; '
                'border-radius: 12px; font-size: 11px; font-weight: bold; '
                'box-shadow: 0 2px 4px rgba(211, 211, 211, 0.3);">❌ Inactive</span>'
            )

    assignment_status.short_description = '🔄 Status'
    assignment_status.admin_order_field = 'is_active'

    def assigned_by_info(self, obj):
        """Enhanced assigned by info"""
        if obj.assigned_by:
            return format_html(
                '<div><small style="color: #6c757d;">👑 {}<br>📧 {}</small></div>',
                obj.assigned_by.full_name, obj.assigned_by.email
            )
        return format_html('<span style="color: #6c757d;">—</span>')

    assigned_by_info.short_description = '👑 Assigned By'

    def get_queryset(self, request):
        """Optimize queries"""
        qs = super().get_queryset(request)
        return qs.select_related('user', 'staff', 'assigned_by')

    def formfield_for_foreignkey(self, db_field, request, **kwargs):
        """Enhanced field filtering"""
        if db_field.name == "staff":
            kwargs["queryset"] = CustomUser.objects.filter(
                user_type__in=['STAFF', 'SUPERUSER'], is_active=True
            ).order_by('full_name')
        elif db_field.name == "user":
            kwargs["queryset"] = CustomUser.objects.filter(
                user_type='USER', is_active=True
            ).order_by('full_name')
        elif db_field.name == "assigned_by":
            kwargs["queryset"] = CustomUser.objects.filter(
                user_type='SUPERUSER', is_active=True
            ).order_by('full_name')
        return super().formfield_for_foreignkey(db_field, request, **kwargs)


@admin.register(OTPCode)
class OTPCodeAdmin(admin.ModelAdmin):
    """Enhanced OTP Code Admin with ARACT Branding"""

    list_display = [
        'user_info', 'otp_masked', 'purpose_badge',
        'created_at', 'expires_at', 'validity_status'
    ]
    list_filter = ['purpose', 'is_used', 'created_at', 'expires_at']
    search_fields = ['user__email', 'user__full_name']
    readonly_fields = [
        'user', 'otp_code', 'purpose', 'created_at',
        'expires_at', 'is_used', 'used_at'
    ]
    ordering = ['-created_at']
    list_per_page = 30

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def user_info(self, obj):
        """Enhanced user info"""
        return format_html(
            '<div><strong>👤 {}</strong><br><small style="color: #6c757d;">📧 {}</small></div>',
            obj.user.full_name, obj.user.email
        )

    user_info.short_description = '👤 User'
    user_info.admin_order_field = 'user__email'

    def otp_masked(self, obj):
        """Enhanced OTP masking"""
        if obj.is_used:
            return format_html(
                '<code style="background: #F0FFF0; padding: 4px 8px; border-radius: 4px; '
                'font-family: monospace; color: #2d5a2d; border: 1px solid #90EE90;">🔒 ***{}</code>',
                obj.otp_code[-2:]
            )
        return format_html(
            '<code style="background: #F0FFF0; padding: 4px 8px; border-radius: 4px; '
            'font-family: monospace; color: #2d5a2d; border: 1px solid #90EE90;">🔐 ******</code>'
        )

    otp_masked.short_description = '🔑 OTP Code'

    def purpose_badge(self, obj):
        """Enhanced purpose badge with light green theme"""
        badges = {
            'LOGIN': ('🔐 Login', '#98FB98'),  # Pale Green
            'ACTIVATION': ('✨ Activation', '#90EE90'),  # Light Green
            'PASSWORD_RESET': ('🔄 Reset', '#FFB6C1')  # Light Pink for contrast
        }
        label, color = badges.get(obj.purpose, ('Unknown', '#D3D3D3'))
        text_color = '#2d5a2d' if obj.purpose != 'PASSWORD_RESET' else '#8B0000'
        return format_html(
            '<span style="background: {}; color: {}; padding: 4px 8px; '
            'border-radius: 12px; font-size: 11px; font-weight: bold; '
            'box-shadow: 0 2px 4px rgba(144, 238, 144, 0.3);">{}</span>',
            color, text_color, label
        )

    purpose_badge.short_description = '🎯 Purpose'

    def validity_status(self, obj):
        """Enhanced validity status with light green theme"""
        if obj.is_valid():
            return format_html(
                '<span style="background: #90EE90; color: #2d5a2d; padding: 4px 8px; '
                'border-radius: 12px; font-size: 11px; font-weight: bold; '
                'box-shadow: 0 2px 4px rgba(144, 238, 144, 0.3);">✅ Valid</span>'
            )
        elif obj.is_used:
            return format_html(
                '<span style="background: #D3D3D3; color: #696969; padding: 4px 8px; '
                'border-radius: 12px; font-size: 11px; font-weight: bold; '
                'box-shadow: 0 2px 4px rgba(211, 211, 211, 0.3);">🔒 Used</span>'
            )
        else:
            return format_html(
                '<span style="background: #FFE4B5; color: #8B4513; padding: 4px 8px; '
                'border-radius: 12px; font-size: 11px; font-weight: bold; '
                'box-shadow: 0 2px 4px rgba(255, 228, 181, 0.3);">⏰ Expired</span>'
            )

    validity_status.short_description = '📊 Status'


@admin.register(CustomAuthToken)
class CustomAuthTokenAdmin(admin.ModelAdmin):
    """Enhanced Authentication Token Admin with ARACT Branding"""

    list_display = [
        'user_info', 'token_preview', 'token_status',
        'created_at', 'expires_at', 'last_used'
    ]
    list_filter = [
        'is_active', 'created_at', 'expires_at', 'user__user_type'
    ]
    search_fields = ['user__email', 'user__full_name']
    readonly_fields = ['token', 'created_at', 'last_used']
    ordering = ['-created_at']
    list_per_page = 25

    fieldsets = (
        ('🔑 Token Information', {
            'fields': ('user', 'token', 'is_active'),
            'classes': ('wide',)
        }),
        ('⏰ Timestamps', {
            'fields': ('created_at', 'expires_at', 'last_used'),
            'classes': ('wide',)
        }),
        ('📱 Device Information', {
            'fields': ('device_info',),
            'classes': ('collapse', 'wide')
        })
    )

    def user_info(self, obj):
        """Enhanced user info with light green theme"""
        colors = {
            'SUPERUSER': '#32CD32',  # Lime Green
            'STAFF': '#90EE90',  # Light Green
            'USER': '#98FB98'  # Pale Green
        }
        icons = {
            'SUPERUSER': '👑',
            'STAFF': '👨‍💼',
            'USER': '👤'
        }

        color = colors.get(obj.user.user_type, '#D3D3D3')
        icon = icons.get(obj.user.user_type, '❓')

        return format_html(
            '<div><strong>{} {}</strong><br><small style="color: #6c757d;">📧 {}</small><br>'
            '<span style="background: {}; color: #2d5a2d; padding: 2px 6px; border-radius: 8px; '
            'font-size: 10px; font-weight: bold; box-shadow: 0 1px 3px rgba(144, 238, 144, 0.3);">{}</span></div>',
            icon, obj.user.full_name, obj.user.email,
            color, obj.user.get_user_type_display()
        )

    user_info.short_description = '👤 User'
    user_info.admin_order_field = 'user__email'

    def token_preview(self, obj):
        """Enhanced token preview with light green theme"""
        return format_html(
            '<code style="background: #F0FFF0; padding: 4px 8px; border-radius: 4px; '
            'font-family: monospace; font-size: 12px; color: #2d5a2d; border: 1px solid #90EE90;">'
            '🔑 {}...{}</code>',
            obj.token[:12], obj.token[-8:]
        )

    token_preview.short_description = '🔑 Token'

    def token_status(self, obj):
        """Enhanced token status with light green theme"""
        if obj.is_valid():
            if obj.expires_at:
                from django.utils import timezone
                remaining = obj.expires_at - timezone.now()
                if remaining.days > 1:
                    return format_html(
                        '<span style="background: #90EE90; color: #2d5a2d; padding: 4px 8px; '
                        'border-radius: 12px; font-size: 11px; font-weight: bold; '
                        'box-shadow: 0 2px 4px rgba(144, 238, 144, 0.3);">✅ Valid</span><br>'
                        '<small style="color: #6c757d;">⏰ {} days left</small>',
                        remaining.days
                    )
                else:
                    return format_html(
                        '<span style="background: #FFE4B5; color: #8B4513; padding: 4px 8px; '
                        'border-radius: 12px; font-size: 11px; font-weight: bold; '
                        'box-shadow: 0 2px 4px rgba(255, 228, 181, 0.3);">⚠️ Expiring Soon</span><br>'
                        '<small style="color: #6c757d;">⏰ {} hours left</small>',
                        remaining.seconds // 3600
                    )
            else:
                return format_html(
                    '<span style="background: #90EE90; color: #2d5a2d; padding: 4px 8px; '
                    'border-radius: 12px; font-size: 11px; font-weight: bold; '
                    'box-shadow: 0 2px 4px rgba(144, 238, 144, 0.3);">✅ Valid</span><br>'
                    '<small style="color: #6c757d;">♾️ No Expiry</small>'
                )
        else:
            return format_html(
                '<span style="background: #FFB6C1; color: #8B0000; padding: 4px 8px; '
                'border-radius: 12px; font-size: 11px; font-weight: bold; '
                'box-shadow: 0 2px 4px rgba(255, 182, 193, 0.3);">❌ Invalid</span>'
            )

    token_status.short_description = '📊 Status'

    actions = ['revoke_tokens', 'refresh_user_tokens', 'export_tokens']

    def revoke_tokens(self, request, queryset):
        """Bulk revoke tokens"""
        updated = queryset.update(is_active=False)
        self.message_user(
            request,
            f'🔒 {updated} token(s) were successfully revoked.',
            level='WARNING'
        )

    revoke_tokens.short_description = "🔒 Revoke selected tokens"

    def refresh_user_tokens(self, request, queryset):
        """Refresh user tokens"""
        user_tokens = queryset.filter(user__user_type='USER', is_active=True)
        count = 0
        for token in user_tokens:
            if hasattr(token, 'refresh'):
                token.refresh()
                count += 1

        self.message_user(
            request,
            f'🔄 {count} user token(s) were successfully refreshed.',
            level='SUCCESS'
        )

    refresh_user_tokens.short_description = "🔄 Refresh selected user tokens"

    def export_tokens(self, request, queryset):
        """Export token data"""
        import csv
        from django.http import HttpResponse
        from datetime import datetime

        response = HttpResponse(content_type='text/csv')
        response[
            'Content-Disposition'] = f'attachment; filename="aract_tokens_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv"'

        writer = csv.writer(response)
        writer.writerow(['User Email', 'User Type', 'Token Preview', 'Created', 'Expires', 'Status', 'Last Used'])

        for token in queryset:
            writer.writerow([
                token.user.email,
                token.user.get_user_type_display(),
                f"{token.token[:12]}...{token.token[-8:]}",
                token.created_at.strftime('%Y-%m-%d %H:%M'),
                token.expires_at.strftime('%Y-%m-%d %H:%M') if token.expires_at else 'No Expiry',
                'Valid' if token.is_valid() else 'Invalid',
                token.last_used.strftime('%Y-%m-%d %H:%M') if token.last_used else 'Never'
            ])

        self.message_user(request, f'📊 Exported {queryset.count()} tokens to CSV.')
        return response

    export_tokens.short_description = "📊 Export selected tokens to CSV"


# ARACT BATT PULSE Admin Site Customization
admin.site.site_header = format_html(
    '<div style="display: flex; align-items: center; gap: 15px;">'
    '<img src="/static/admin/img/aract_logo.png" alt="ARACT Logo" style="height: 40px; width: auto;" onerror="this.style.display=\'none\'">'
    '<div>'
    '<div style="font-size: 24px; font-weight: bold; color: #00000;">ARACT BATT PULSE</div>'
    '<div style="font-size: 12px; color: #90EE90; margin-top: -2px;">Battery Monitoring System</div>'
    '</div>'
    '</div>'
)

admin.site.site_title = "ARACT BATT PULSE Admin"
admin.site.index_title = format_html(
    '<div style="text-align: center; padding: 20px; background: linear-gradient(135deg, #F0FFF0 0%, #E0FFE0 100%); '
    'border-radius: 12px; margin-bottom: 20px; border: 2px solid #90EE90;">'
    '<h1 style="color: #2d5a2d; margin: 0; font-size: 28px;">🔋 Welcome to ARACT BATT PULSE</h1>'
    '<p style="color: #4d7a4d; margin: 10px 0 0 0; font-size: 16px;">Advanced Battery Monitoring & Management System</p>'
    '<div style="margin-top: 15px; display: flex; justify-content: center; gap: 20px; flex-wrap: wrap;">'

    '</div>'
    '</div>'
)