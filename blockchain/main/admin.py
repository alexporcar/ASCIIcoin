from django.contrib import admin, messages
from django.contrib.auth.models import Group
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.translation import ngettext
from main.models import MyUser, Wallet, Node
from main.forms import MyUserCreationForm, UserChangeForm

class UserAdmin(BaseUserAdmin):
    @admin.action(description='Deactivate selected Users')
    def deactivate_users(self, request, queryset):
        updated = queryset.update(is_active=False)
        self.message_user(request, ngettext(
            '%d user was successfully deactivated.',
            '%d users were successfully deactivated.',
            updated,
        ) % updated, messages.SUCCESS)
    
    @admin.action(description='Activate selected Users')
    def activate_users(self, request, queryset):
        updated = queryset.update(is_active=True)
        self.message_user(request, ngettext(
            '%d user was successfully activated.',
            '%d users were successfully activated.',
            updated,
        ) % updated, messages.SUCCESS)

    @admin.action(description='Promote selected Users')
    def make_admin(self, request, queryset):
        updated = queryset.update(is_admin=True)
        self.message_user(request, ngettext(
            '%d user was successfully promoted to admin.',
            '%d users were successfully promoted to admin.',
            updated,
        ) % updated, messages.SUCCESS)
    
    @admin.action(description='Downgrade selected Users')
    def remove_admin(self, request, queryset):
        updated = queryset.update(is_admin=False)
        self.message_user(request, ngettext(
            '%d user was successfully downgraded from admin.',
            '%d users were successfully downgraded from admin.',
            updated,
        ) % updated, messages.SUCCESS)
    
    def delete_queryset(self, request, queryset):
        for user in queryset:
            try:
                user = MyUser.objects.get(email=user)
                # deleting the wallet, the user is also deleted
                user.address.delete()
            except:
                pass

    # the forms to add and change user instances
    form = UserChangeForm
    add_form = MyUserCreationForm

    # the fields to be used in displaying MyUser model
    list_display = ('email', 'address', 'is_admin', 'is_active')
    list_filter = ('is_admin', 'is_active')
    fieldsets = (
        ('Account', {'fields': ('email', 'password', 'address')}),
        ('Permissions', {'fields': ('is_admin', 'is_active')}),
    )
    
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'password1', 'password2'),
        }),
    )
    search_fields = ('email',)
    ordering = ('email',)
    filter_horizontal = ()

    actions = ('delete_selected', deactivate_users, activate_users, make_admin, remove_admin)


class WalletAdmin(admin.ModelAdmin):
    list_display = ('address',)
    readonly_fields = ('address', 'encrypted_private_key', 'public_key',)
    search_fields = ('address',)
    actions = None

admin.site.register(MyUser, UserAdmin)
admin.site.register(Wallet, WalletAdmin)
admin.site.register(Node)
admin.site.unregister(Group)