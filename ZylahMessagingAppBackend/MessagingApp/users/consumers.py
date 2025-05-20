'''fully final code'''

import json
import logging
import pytz
from asgiref.sync import sync_to_async
from .models import Message, Group
from datetime import datetime
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.db.models import Q
from rest_framework_simplejwt.tokens import UntypedToken
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from channels.generic.websocket import AsyncWebsocketConsumer


logger = logging.getLogger(__name__)
User = get_user_model()

class ChatConsumer(AsyncWebsocketConsumer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.room_name = None
        self.user = None
        self.receiver = None

    async def connect(self):
        token = self._get_token_from_headers()
        if not token:
            logger.error("Authorization token is missing.")
            await self.close()
            return

        self.user = await self._authenticate_user(token)
        if not self.user:
            logger.error("User authentication failed.")
            await self.close()
            return

        self.receiver_email = self.scope['url_route']['kwargs']['receiver_email']
        self.receiver = await self.get_user_by_email(self.receiver_email)
        if not self.receiver:
            logger.error(f"Receiver with email '{self.receiver_email}' does not exist.")
            await self.close()
            return

        if self.user.email < self.receiver.email:
            self.room_name = f"chat_{self.user.email}_{self.receiver.email}".replace('@', '_').replace('.', '_')
        else:
            self.room_name = f"chat_{self.receiver.email}_{self.user.email}".replace('@', '_').replace('.', '_')

        await self.channel_layer.group_add(self.room_name, self.channel_name)
        await self.accept()
        
        unread_messages = await self._get_unread_messages()
        if unread_messages:
            for message in unread_messages:
                await self.send(text_data=json.dumps({
                    "type": "chat_message",
                    "message": message['content'],
                    "sender": message['sender_email'],
                    "timestamp": message['timestamp'].isoformat(),
                }))
            
            await self._mark_messages_as_read(self.receiver.email, self.user.email)
            
            for message in unread_messages:
                await self.channel_layer.group_send(
                    self.room_name,
                    {
                        "type": "read_receipt",
                        "sender": message['sender_email'],
                        "receiver": self.user.email,
                        "message": message['content'],
                        'timestamp' : message['timestamp'].isoformat()
                    },
                )

        logger.info(f"WebSocket connected: {self.channel_name} joined {self.room_name}")

    async def disconnect(self, close_code):
        if self.room_name:
            await self.channel_layer.group_discard(self.room_name, self.channel_name)
        logger.info(f"WebSocket disconnected: {self.channel_name} left {self.room_name}")

    async def receive(self, text_data):
        try:
            data = json.loads(text_data)
            content = data.get("message", "")
            
            if not content:
                logger.error("Received empty message content.")
                return

            sender = self.user
            receiver = self.receiver
        
            message = await self._save_message(sender, receiver, content)
            current_time = message['timestamp'].isoformat()

            logger.info(f"Message received and saved: {sender.email} -> {receiver.email}: {content}")

            await self.channel_layer.group_send(
                self.room_name,
                {
                    "type": "chat_message",
                    "message": content,
                    "sender": sender.email,
                    "receiver": receiver.email,
                    "timestamp": current_time,
                },
            )
        except Exception as e:
            logger.error(f"Error in receive: {str(e)}")
            await self.send(text_data=json.dumps({
                "type": "error",
                "message": "Failed to process message"
            }))

    async def chat_message(self, event):
        """
        Handle incoming chat messages and read receipts.
        """
        try:
            await self.send(text_data=json.dumps({
                "type": "chat_message",
                "message": event["message"],
                "sender": event["sender"],
                "timestamp": event.get("timestamp"),
            }))
            if event["receiver"] == self.user.email:
                await self._mark_messages_as_read(event["sender"], event["receiver"])
                current_time = timezone.now().isoformat()

                await self.channel_layer.group_send(
                    self.room_name,
                    {
                        "type": "read_receipt",
                        "sender": event["sender"],
                        "receiver": self.user.email,
                        "message": event["message"],
                        "timestamp": current_time,  
                    },
                )
        except Exception as e:
            logger.error(f"Error in chat_message: {str(e)}")


    async def read_receipt(self, event):
        """
        Handle read receipt notifications
        """
        try:
            if event["sender"] == self.user.email:
                timestamp_str = event.get("timestamp")
                timestamp = datetime.fromisoformat(timestamp_str)
                ist_timezone = pytz.timezone('Asia/Kolkata')
                timestamp_ist = timestamp.astimezone(ist_timezone)
                timestamp_ist_str = timestamp_ist.isoformat()

                logger.info(f"Sending read receipt to {self.user.email} for message: {event['message']}")
                await self.send(text_data=json.dumps({
                    "type": "read_receipt",
                    "message": event["message"],
                    "receiver": event["receiver"],
                    "status": "read",
                    "timestamp": timestamp_ist_str,  
                }))
        except Exception as e:
            logger.error(f"Error in read_receipt: {str(e)}")

    @staticmethod
    @sync_to_async
    def get_user_by_email(email):
        try:
            return User.objects.get(email=email)
        except User.DoesNotExist:
            return None
        
    @sync_to_async
    def _save_message(self, sender, receiver, content):
        ist_timezone = pytz.timezone('Asia/Kolkata')
        current_time_ist = timezone.now().astimezone(ist_timezone)
        logger.info(current_time_ist)
        message = Message.objects.create(
            sender=sender,
            receiver=receiver,
            content=content,
            is_read=False,
            timestamp=current_time_ist
        )
        logger.info(current_time_ist)
        return {
            'content': message.content,
            'timestamp': message.timestamp,
            'sender_email': sender.email
        }

    @sync_to_async
    def _get_unread_messages(self):
        """
        Get all unread messages for the current user from the specific sender
        """
        messages = Message.objects.filter(
            Q(sender=self.receiver, receiver=self.user, is_read=False)
        ).order_by('timestamp')
        
        return [{
            'content': msg.content,
            'timestamp': msg.timestamp,
            'sender_email': msg.sender.email
        } for msg in messages]

    @sync_to_async
    def _mark_messages_as_read(self, sender_email, receiver_email):
        """
        Mark all unread messages between sender and receiver as read
        """
        try:
            sender = User.objects.get(email=sender_email)
            receiver = User.objects.get(email=receiver_email)
            
            unread_messages = Message.objects.filter(
                sender=sender,
                receiver=receiver,
                is_read=False
            )
            
            updated_count = unread_messages.update(is_read=True)
            logger.info(f"Marked {updated_count} messages as read from {sender_email} to {receiver_email}")
            
            return updated_count
        except Exception as e:
            logger.error(f"Error marking messages as read: {e}")
            return 0

    def _get_token_from_headers(self):
        headers = self.scope.get('headers', [])
        for header in headers:
            if header[0] == b'authorization':
                return header[1].decode().split(' ')[1]
        return None

    async def _authenticate_user(self, token):
        try:
            user = await sync_to_async(self.decode_token)(token)
            return user
        except Exception as e:
            logger.error(f"JWT Authentication error: {e}")
            return None

    def decode_token(self, token):
        try:
            UntypedToken(token)
            user_id = UntypedToken(token).payload.get('user_id')
            return User.objects.get(id=user_id)
        except (InvalidToken, TokenError, User.DoesNotExist):
            return None
        

class GroupChatConsumer(AsyncWebsocketConsumer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.group_name = None
        self.user = None
        self.group = None
        self.sender_name = None

    async def connect(self):
        token = self._get_token_from_headers()
        if not token:
            logger.error("Authorization token is missing.")
            await self.close()
            return

        self.user = await self._authenticate_user(token)
        if not self.user:
            logger.error("User authentication failed.")
            await self.close()
            return

        self.group_name = self.scope['url_route']['kwargs']['group_name']
        self.sender_name = self.scope['url_route']['kwargs']['sender_name']

        self.group = await self.get_group_by_name(self.group_name)
        if not self.group:
            logger.error(f"Group with name '{self.group_name}' does not exist.")
            await self.close()
            return

        if not await self.is_user_in_group(self.user, self.group):
            logger.error(f"User '{self.user.email}' is not a member of the group.")
            await self.close()
            return

        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()

        unread_messages = await self._get_unread_group_messages()
        if unread_messages:
            for message in unread_messages:
                await self.send(text_data=json.dumps({
                    "type": "group_chat_message",
                    "message": message['content'],
                    "sender": message['sender_email'],
                    "timestamp": message['timestamp'].isoformat(),
                }))

            await self._mark_messages_as_read(self.user, self.group)
            for message in unread_messages:

                await self.channel_layer.group_send(
                        self.group_name,
                        {
                            "type": "read_receipt",
                            "sender": message["sender_email"],
                            "receiver": self.user.email,  
                            "message": message["content"],
                            'timestamp' : message['timestamp'].isoformat()
                        },
                    )
            logger.info(f"Marked unread messages as read for user {self.user.email} in group {self.group.name}")

        logger.info(f"WebSocket connected: {self.channel_name} joined group {self.group_name}")

    async def disconnect(self, close_code):
        if self.group_name:
            await self.channel_layer.group_discard(self.group_name, self.channel_name)
        logger.info(f"User {self.user.email} disconnected from group {self.group_name}")

    async def receive(self, text_data):
        try:
            data = json.loads(text_data)
            content = data.get("message", "")

            if not content:
                logger.error("Received empty message content.")
                return

            sender = self.user
            recipients = await self._get_group_members(self.group)
            message = await self._save_group_message(sender, self.group, content, recipients)

            logger.info(f"Group message saved: {sender.email} -> {self.group.name}: {content}")
            await self.channel_layer.group_send(
                self.group_name,
                {
                    "type": "group_chat_message",
                    "message": content,
                    "sender": sender.email,
                    "sender_name": self.sender_name,
                    "group": self.group.name,
                    "timestamp": message['timestamp'].isoformat(),
                },
            )
        except Exception as e:
            logger.error(f"Error in receive: {str(e)}")
            await self.send(text_data=json.dumps({
                "type": "error",
                "message": "Failed to process message"
            }))

    async def group_chat_message(self, event):
        try:
            group = await self.get_group_by_name(event["group"])

            await self.send(text_data=json.dumps({
                "type": "group_chat_message",
                "message": event["message"],
                "sender": event["sender"],
                "sender_name": event["sender_name"],
                "group": event["group"],
                "timestamp": event.get("timestamp"),
            }))
            current_time = timezone.now().isoformat()
            if self.user.email != event["sender"]:
                await self._mark_message_as_read_for_user(self.user, group)
                await self.channel_layer.group_send(
                    self.group_name,
                    {
                        "type": "read_receipt",
                        "sender": event["sender"],
                        "receiver": self.user.email,  
                        "message": event["message"],
                        "timestamp": current_time,  
                    },
                )
        except Exception as e:
            logger.error(f"Error in group_chat_message: {str(e)}")

    async def read_receipt(self, event):
        """
        Handle read receipt notifications for group chat.
        """
        try:
            if event["sender"] == self.user.email:
                timestamp_str = event.get("timestamp")
                timestamp = datetime.fromisoformat(timestamp_str)

                ist_timezone = pytz.timezone('Asia/Kolkata')
                timestamp_ist = timestamp.astimezone(ist_timezone)

                timestamp_ist_str = timestamp_ist.isoformat()

                logger.info(f"Sending read receipt to {self.user.email} for message: {event['message']}")
                await self.send(text_data=json.dumps({
                    "type": "read_receipt",
                    "message": event["message"],
                    "receiver": event["receiver"],
                    "status": "read",
                    "timestamp": timestamp_ist_str,  
                }))
        except Exception as e:
            logger.error(f"Error in read_receipt: {str(e)}")


    @sync_to_async
    def _get_group_members(self, group):
        return list(group.members.all())

    @sync_to_async
    def _save_group_message(self, sender, group, content, recipients):
        """
        Save the message for all group members with individual `is_read` statuses.
        """
        ist_timezone = pytz.timezone('Asia/Kolkata')
        current_time_ist = timezone.now().astimezone(ist_timezone)
        messages = []
    
        for recipient in recipients:
            if recipient != sender:
                print(recipient,sender)  
                messages.append(Message(
                    sender=sender,
                    group=group,
                    receiver=recipient,
                    content=content,
                    is_read=False,
                    timestamp=current_time_ist
                ))

        if messages:
            Message.objects.bulk_create(messages)

        return {
            'content': content,
            'timestamp': current_time_ist,
            'sender_email': sender.email,
        }

    @sync_to_async
    def _get_unread_group_messages(self):
        """
        Get all unread messages for the current user in the group.
        """
        messages = Message.objects.filter(
            group=self.group,
            receiver=self.user,
            is_read=False
        ).order_by('timestamp')

        return [{
            'content': msg.content,
            'timestamp': msg.timestamp,
            'sender_email': msg.sender.email,
        } for msg in messages]

    @sync_to_async
    def _mark_messages_as_read(self, user, group):
        """
        Mark unread messages for a user in the group as read.
        """
        unread_messages = Message.objects.filter(
            group=group,
            receiver=user,
            is_read=False
        )
        updated_count = unread_messages.update(is_read=True)
        logger.info(f"Marked {updated_count} messages as read for user {user.email} in group {group.name}")
        return updated_count

    @sync_to_async
    def _mark_message_as_read_for_user(self, user, group):
        """
        Mark unread messages from the group for this user as read.
        """
        unread_messages = Message.objects.filter(
            group=group,
            receiver=user,
            is_read=False
        )
        logger.info(unread_messages)
        updated_count = unread_messages.update(is_read=True)
        logger.info(f"Marked {updated_count} messages as read for user {user.email} in group {group.name}")
        return updated_count

    @staticmethod
    @sync_to_async
    def get_group_by_name(group_name):
        try:
            return Group.objects.get(name=group_name)
        except Group.DoesNotExist:
            return None

    @sync_to_async
    def is_user_in_group(self, user, group):
        return group.members.filter(id=user.id).exists()

    def _get_token_from_headers(self):
        headers = self.scope.get('headers', [])
        for header in headers:
            if header[0] == b'authorization':
                return header[1].decode().split(' ')[1]
        return None

    async def _authenticate_user(self, token):
        try:
            user = await sync_to_async(self.decode_token)(token)
            return user
        except Exception as e:
            logger.error(f"JWT Authentication error: {e}")
            return None

    def decode_token(self, token):
        try:
            UntypedToken(token)
            user_id = UntypedToken(token).payload.get('user_id')
            return get_user_model().objects.get(id=user_id)
        except (InvalidToken, TokenError, get_user_model().DoesNotExist):
            return None

