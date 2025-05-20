import os
import pytz
from datetime import timedelta
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.utils import timezone
from django.conf import settings
from django.utils.timezone import now


IST = pytz.timezone('Asia/Kolkata')
def get_ist_time():
    """Return the current time in IST."""
    return now().astimezone(IST)


class CustomUserManager(BaseUserManager):
    """Manager for custom user model."""
    def create_user(self, email, password=None, **extra_fields):
        """Create and return a regular user."""
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        extra_fields.setdefault('is_active', False)
        groups=extra_fields.pop('groups',None)
        user_permissions = extra_fields.pop("user_permissions", None)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)

        if groups:
            user.groups.set(groups)

        if user_permissions:
            user.user_permissions.set(user_permissions)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        """Create and return a superuser."""
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)


        if not extra_fields.get('is_staff'):
            raise ValueError('Superuser must have is_staff=True.')
        if not extra_fields.get('is_superuser'):
            raise ValueError('Superuser must have is_superuser=True.')
        if not extra_fields.get('is_active'):
            raise ValueError('Superuser must have is_active=True.')

        return self.create_user(email, password, **extra_fields)
    

class User(AbstractBaseUser, PermissionsMixin):
    """Custom user model."""
   

    first_name = models.CharField(max_length=150, blank=False)
    last_name = models.CharField(max_length=150, blank=False)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=128)
    phone_number = models.CharField(max_length=15, unique=False, blank=True)
    profile_pic = models.ImageField(upload_to='profile_pic/',  null=True,blank=True)
    face_encoding_file = models.FileField(upload_to='face_encodings/', null=True, blank=True)  
    otp = models.CharField(max_length=6, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=False)
    is_staff= models.BooleanField(default=False)
    is_blocked= models.BooleanField(default=False)
    flag_count=models.IntegerField(default=0)

    
    def delete(self, args, *kwargs):
        if self.profile_picture:
            if os.path.isfile(self.profile_picture.path):
                os.remove(self.profile_picture.path)
        if self.face_encoding_file:
            if os.path.isfile(self.face_encoding_file.path):
                os.remove(self.face_encoding_file.path)
        super().delete(*args, **kwargs)

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name']

    def __str__(self):
        return self.email
    
    def is_otp_expired(self):
        """Check if OTP is expired."""
        if self.otp_created_at:
            return timezone.now() > self.otp_created_at + timedelta(minutes=10)  
        return True
    
    def delete(self, *args, **kwargs):
        super(User, self).delete(*args, **kwargs)  
    
    
class Message(models.Model):
    """Model to store messages between users."""
    sender = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='sent_messages'
    )
    receiver = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='received_messages',
        null =True
    )
    group= models.ForeignKey(
        'Group',  # Reference to the Group model
        on_delete=models.CASCADE,
        related_name='messages',
        null=True,
        blank=True,
        help_text="The group this message belongs to."
    )

    content = models.TextField(blank=True, null=True)
    timestamp = models.DateTimeField()   
    is_read = models.BooleanField(default=False)
    
    class Meta:
        ordering = ['-timestamp']  

    def __str__(self):
        return f"Message from {self.sender} to {self.receiver or 'group'}"
    

class Group(models.Model):
    """Model for managing user groups."""
    name = models.CharField(max_length=255, unique=True, help_text=("The name of the group."))
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="created_groups",
        help_text="The user who created the group."
    )
    admins = models.ManyToManyField(
        settings.AUTH_USER_MODEL,
        related_name="admin_groups",
        blank=True,
        help_text="Users with admin privileges in the group."
    )
    members = models.ManyToManyField(
        settings.AUTH_USER_MODEL,
        related_name="member_groups",
        blank=True,
        help_text="All members of the group."
    )
    group_pic = models.ImageField(
        upload_to='group_pics/', 
        blank=True, 
        null=True,
        help_text="Profile picture for the group."
    )
    created_at = models.DateTimeField(default=get_ist_time)
    updated_at = models.DateTimeField(default=get_ist_time)

    def save(self, *args, **kwargs):
        if not self.pk:  
            self.created_at = now().astimezone(IST)
        super().save(*args, **kwargs)

    def __str__(self):
        return self.name
    
class GroupMember(models.Model):
    """Model for managing group membership."""
    ROLE_CHOICES = [
        ('member', ('Member')),
        ('admin', ('Admin')),
    ]

    group = models.ForeignKey(
        'Group', 
        on_delete=models.CASCADE, 
        related_name='group_members', 
        help_text=("The group to which the user belongs.")
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.CASCADE, 
        related_name='group_memberships', 
        help_text=("The user who is a member of the group.")
    )
    join_date = models.DateTimeField(default=timezone.now, help_text=("The date and time when the user joined the group."))
    role = models.CharField(
        max_length=10, 
        choices=ROLE_CHOICES, 
        default='member', 
        help_text=("The role of the user in the group (member/admin).")
    )

    class Meta:
        unique_together = ('group', 'user')  
        verbose_name = ('Group Member')
        verbose_name_plural = ('Group Members')
        ordering = ['-join_date']

    def __str__(self):
        return f"{self.user.email} in {self.group.name} as {self.role}"
    
    
class Subscription(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    stripe_customer_id = models.CharField(max_length=255)
    stripe_subscription_id = models.CharField(max_length=255)
    is_active = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class Flag(models.Model):
    """Model to store flagged messages."""
    
    message = models.ForeignKey(
        Message,
        on_delete=models.CASCADE,
        related_name='flags',
        help_text="The message that has been flagged."
    )
    created_at = models.DateTimeField(
        default=timezone.now,
        help_text="The time when the flag was created."
    )
    reviewed = models.BooleanField(
        default=False, 
        help_text="Whether the flagged message has been reviewed."
    )
    class Meta:
        ordering = ['-created_at']  # Orders flags by most recent first
        verbose_name = 'Flag'
        verbose_name_plural = 'Flags'

    def __str__(self):
        return f"Flag on message {self.message.id}"

 
