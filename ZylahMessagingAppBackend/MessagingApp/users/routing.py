from django.urls import re_path
from users.consumers import ChatConsumer,GroupChatConsumer

websocket_urlpatterns = [
    re_path(r'ws/chat/(?P<sender_email>[^/]+)/(?P<receiver_email>[^/]+)/$', ChatConsumer.as_asgi()),
    re_path(r'ws/group/(?P<group_name>[^/]+)/(?P<sender_name>[^/]+)/$', GroupChatConsumer.as_asgi(), name='group_chat'),
]
