# admin.py

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import User,Role,Company,Employee,Admin,HR

class CustomUserAdmin(UserAdmin):
    model = User
    list_display = ['email', 'username', 'first_name', 'last_name', 'is_staff', 'is_active','verified']
    list_filter = ['is_staff', 'is_superuser', 'is_active']
    search_fields = ['email', 'username']
    ordering = ['email']
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Personal Info', {'fields': ('first_name', 'last_name', 'date_of_birth', 'profile_picture')}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        ('Important Dates', {'fields': ('last_login', 'date_joined')}),
    )
    add_fieldsets = (
        (None, {'fields': ('email', 'password1', 'password2')}),
        ('Personal Info', {'fields': ('username','first_name', 'last_name', 'date_of_birth', 'profile_picture')}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser')}),
    )

admin.site.register(User, CustomUserAdmin)
admin.site.register(Role)
admin.site.register(Company)
admin.site.register(Employee)
admin.site.register(Admin)
admin.site.register(HR)






