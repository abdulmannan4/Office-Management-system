from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.utils import timezone
from django.contrib.auth.models import Group
from django.db.models.signals import post_save
from django.dispatch import receiver

class CustomUserManager(BaseUserManager):
    def create_user(self, email, username, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, username=username, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, username, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        return self.create_user(email, username, password, **extra_fields)
    
class User(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True)
    username = models.CharField(max_length=150, unique=True)
    first_name = models.CharField(max_length=30)
    last_name = models.CharField(max_length=30)
    date_joined = models.DateTimeField(default=timezone.now)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    is_superuser = models.BooleanField(default=False)
    date_of_birth = models.DateField(null=True, blank=True)
    # profile_picture = models.ImageField(upload_to='profile_pics/', null=True, blank=True)
    verified = models.BooleanField(default=False)

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username', 'first_name', 'last_name']

    def __str__(self):
        return self.username

    def get_full_name(self):
        return f"{self.first_name} {self.last_name}"

    class Meta:
        verbose_name = 'User'
        verbose_name_plural = 'Users'


@receiver(post_save, sender=User)
def create_groups_when_user_created(sender, instance, created, **kwargs):
    if created:
        # Define the group names
        group_name1 = 'HR'
        group_name2 = 'Admin'
        group_name3 = 'Employee'

        # Create or get the groups (they won't be duplicated)
        Group.objects.get_or_create(name=group_name1)
        Group.objects.get_or_create(name=group_name2)
        Group.objects.get_or_create(name=group_name3)




class Role(models.Model):
    ROLE_CHOICES = [
        ('HR', 'HR'),
        ('ADMIN', 'Admin'),
        ('EMPLOYEE', 'Employee'),
    ]

    name = models.CharField(
        max_length=15,
        choices=ROLE_CHOICES,
        default='EMPLOYEE',
    )
   

    def __str__(self):
        return self.name


class Company(models.Model):

    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(null=True, blank=True)
    address = models.CharField(max_length=255, null=True, blank=True)
    phone_number = models.CharField(max_length=15, null=True, blank=True)
    email = models.EmailField(null=True, blank=True)
    website = models.URLField(null=True, blank=True)
    registration_number = models.CharField(max_length=20, null=False, blank=False, unique=True)
    country = models.CharField(max_length=100, null=True, blank=True)
    logo = models.ImageField(upload_to='company_logos/', null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return self.name



class Department(models.Model):
    name = models.CharField(max_length=100)
    def __str__(self):
        return self.name

class Employee(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    company = models.ForeignKey(Company, on_delete=models.CASCADE)
    department = models.ForeignKey(Department,on_delete=models.SET_NULL, null=True,max_length=100)
    job_title = models.CharField(max_length=100)
    role = models.ForeignKey(Role, on_delete=models.SET_NULL, null=True, blank=True)
    def save(self, *args, **kwargs):
        if not self.role:
            # Automatically set the role to "Admin" if not already assigned
            self.role = Role.objects.get(name=Role.EMPLOYEE)
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.user.username} - {self.company.name} - {self.role.name if self.role else 'No Role'}"


class HR(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    company = models.ForeignKey(Company, on_delete=models.CASCADE)
    role = models.ForeignKey(Role, on_delete=models.SET_NULL, null=True, blank=True)
    def save(self, *args, **kwargs):
        if not self.role:
            # Automatically set the role to "Admin" if not already assigned
            self.role = Role.objects.get(name=Role.HR)
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.user.username} - {self.company.name} - {self.role.name if self.role else 'No Role'}"

class Admin(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    company = models.ForeignKey(Company, on_delete=models.CASCADE)
    role = models.ForeignKey(Role, on_delete=models.SET_NULL, null=True, blank=True)

    def save(self, *args, **kwargs):
        if not self.role:
            # Automatically set the role to "Admin" if not already assigned
            self.role = Role.objects.get(name=Role.ADMIN)
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.user.username} - {self.company.name} - {self.role.name if self.role else 'No Role'}"

class Task(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('in_progress', 'In Progress'),
        ('completed', 'Completed'),
        ('overdue', 'Overdue')
    ]
    
    title = models.CharField(max_length=200)
    description = models.TextField()
    assigned_to = models.ForeignKey('User', on_delete=models.CASCADE, related_name='tasks')
    status = models.CharField(max_length=15, choices=STATUS_CHOICES, default='pending')
    deadline = models.DateTimeField()
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    

    def __str__(self):
        return self.title

class Attendance(models.Model):
    employee = models.ForeignKey(Employee,on_delete=models.CASCADE)
    date = models.DateField(default=timezone.now)
    check_in = models.TimeField()
    check_out = models.TimeField()
    status = models.CharField(max_length=10, choices=[('Present', 'Present'), ('Absent', 'Absent')], default='Present')

    def __str__(self):
        return f"{self.employee} - {self.date}"

    class Meta:
        verbose_name = 'Attendance'
        verbose_name_plural = 'Attendance Records'


# Leave Model to manage employee leaves
class Leave(models.Model):
    employee = models.ForeignKey(
        Employee,
        verbose_name=("Employee"),
        on_delete=models.CASCADE
    )
    start_date = models.DateField()
    end_date = models.DateField()
    leave_type = models.CharField(max_length=50, choices=[('Sick Leave', 'Sick Leave'), ('Vacation', 'Vacation'), ('Emergency Leave', 'Emergency Leave')])
    status = models.CharField(max_length=10, choices=[('Pending', 'Pending'), ('Approved', 'Approved'), ('Rejected', 'Rejected')], default='Pending')
    reason = models.TextField()

    def __str__(self):
        return f"{self.employee} - {self.leave_type} ({self.status})"

    class Meta:
        verbose_name = 'Leave'
        verbose_name_plural = 'Leaves'

