from django.db.models.signals import post_save
from django.dispatch import receiver
from django.core.mail import send_mail
from django.conf import settings
from .models import User

@receiver(post_save, sender=User)
def send_profile_update_email(sender, instance, created, **kwargs):
    if not created:  # Only send the email if the user is being updated, not created
        subject = "Profile Updated"
        message = "Your profile has been updated successfully."
        from_email = settings.DEFAULT_FROM_EMAIL
        recipient_list = [instance.email]
        
        send_mail(subject, message, from_email, recipient_list)

