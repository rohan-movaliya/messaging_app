from django.contrib import admin
from .models import *

admin.site.register(User)
admin.site.register(Message)
admin.site.register(Group)
admin.site.register(GroupMember)
admin.site.register(Flag)
admin.site.register(Subscription)
