import logging
import pickle
import httpx
import os
import csv
import requests
from .models import *
from .serializers import *
from .stripe_service import *
from datetime import timedelta
from rest_framework.response import Response
from rest_framework import status,permissions
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated,IsAdminUser
from rest_framework.generics import ListAPIView
from rest_framework.decorators import api_view
from rest_framework.views import APIView
from django.shortcuts import get_object_or_404
from django.core.mail import send_mail
from django.utils.crypto import get_random_string
from django.utils.timezone import now
from django.contrib.auth import get_user_model
from django.contrib.auth import authenticate
from django.core.files.base import ContentFile
from django.http import HttpResponse
from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist
from .permission import IsAdminOrOwner


stripe.api_key = settings.STRIPE_SECRET_KEY
FASTAPI_URL = "http://127.0.0.1:8003"


logger = logging.getLogger(__name__)
User = get_user_model() 


class RegisterView(APIView):
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    
class LoginView(APIView):
    def post(self, request):
        email = request.data.get("email")
        password = request.data.get("password")

        if not email or not password:
            return Response({"error": "Email and password are required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
        except ObjectDoesNotExist:
            return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)

        user = authenticate(request, email= email, password=password)  
        if user is None:
            return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)
        if user.is_superuser:
            refresh = RefreshToken.for_user(user)
            return Response({
                "refresh": str(refresh),
                "access": str(refresh.access_token),
            }, status=status.HTTP_200_OK)
        
        return Response({"message": "Login successful, verify your face..."}, status=status.HTTP_200_OK)
    

class UserListCreateAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        if not request.user.is_staff:
            return Response({'detail': 'Only admins can view all users.'}, status=status.HTTP_403_FORBIDDEN)
        users = User.objects.all()
        serializer = UserSerializer(users, many=True)
        return Response(serializer.data)

    def post(self, request):
        if not request.user.is_staff:
            return Response({'detail': 'Only admins can create users.'}, status=status.HTTP_403_FORBIDDEN)
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class UserDetailAPIView(APIView):
    permission_classes = [IsAdminOrOwner]

    def get_object(self, pk):
        try:
            return User.objects.get(pk=pk)
        except User.DoesNotExist:
            return None

    def get(self, request, pk):
        user = self.get_object(pk)
        if not user:
            return Response({'detail': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)
        if request.user.is_staff or user == request.user:
            serializer = UserSerializer(user)
            return Response(serializer.data)
        
        return Response({'detail': 'You do not have permission to view this user data.'}, status=status.HTTP_403_FORBIDDEN)

    def put(self, request, pk):
        """Update user data"""
        user = self.get_object(pk)
        if not user:
            return Response({'detail': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)
        
        if request.user.is_staff or user == request.user:
            serializer = UserSerializer(user, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        return Response({'detail': 'You do not have permission to update this user data.'}, status=status.HTTP_403_FORBIDDEN)

    def delete(self, request, pk):
        """Delete user data"""
        user = self.get_object(pk)
        if not user:
            return Response({'detail': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)
        
        if user:
            if request.user.is_staff or user == request.user:
                user.delete()
                return Response({'detail': 'User deleted successfully.'}, status=status.HTTP_204_NO_CONTENT)
            
            return Response({'detail': 'You do not have permission to delete this user data.'}, status=status.HTTP_403_FORBIDDEN)
        return Response({'detail': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)

class PasswordResetView(APIView):
    permission_classes = [IsAuthenticated]  

    def post(self, request):
        """ Send OTP only to the owner (not admin) """
        serializer = SendOtpSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        email = serializer.validated_data['email']

        if request.user.email != email:
            return Response({"error": "You can only request OTP for your own account."}, status=status.HTTP_403_FORBIDDEN)
        
        if request.user.is_staff: 
            return Response({"error": "Admins cannot request OTP."}, status=status.HTTP_403_FORBIDDEN)

        try:
            user = get_user_model().objects.get(email=email)
        except get_user_model().DoesNotExist:
            return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)

        otp = get_random_string(length=6, allowed_chars='0123456789')
        user.otp = otp
        user.otp_created_at = now()
        user.otp_expiration = now() + timedelta(minutes=10)  
        user.save()

        send_mail(
            subject='Password Reset OTP',
            message=f'Your OTP for password reset is: {otp}',
            from_email='from@example.com',  
            recipient_list=[email],
            fail_silently=False,
        )

        return Response({"detail": "OTP sent successfully."}, status=status.HTTP_200_OK)

    def patch(self, request):
        """ Allow only owners to reset password using OTP, admins cannot use OTP """
        serializer = ChangePasswordWithOtpSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        email = serializer.validated_data['email']
        otp = serializer.validated_data.get('otp')
        new_password = serializer.validated_data['new_password']

        if request.user.email != email:
            return Response({"error": "You can only change the password for your own account."}, status=status.HTTP_403_FORBIDDEN)

        if request.user.is_staff:
            return Response({"error": "Admins cannot reset passwords using OTP."}, status=status.HTTP_403_FORBIDDEN)

        try:
            user = get_user_model().objects.get(email=email)
        except get_user_model().DoesNotExist:
            return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)

        if user.otp != otp:
            return Response({"error": "Invalid OTP."}, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(new_password)
        user.otp = None  
        user.otp_expiration = None
        user.save()

        return Response({"detail": "Password changed successfully."}, status=status.HTTP_200_OK)


class AdminChangePasswordView(APIView):
    """ Admins can change any user's password without OTP """
    permission_classes = [IsAuthenticated]

    def patch(self, request):
        if not request.user.is_staff:
            return Response({"error": "Only admins can change passwords without OTP."}, status=status.HTTP_403_FORBIDDEN)

        serializer = AdminChangePasswordSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        email = serializer.validated_data['email']
        new_password = serializer.validated_data['new_password']

        try:
            user = get_user_model().objects.get(email=email)
        except get_user_model().DoesNotExist:
            return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)

        user.set_password(new_password)
        user.save()

        return Response({"detail": "Password changed successfully by admin."}, status=status.HTTP_200_OK)

 
class GroupAPIView(APIView):
    """
    API for creating and managing groups.
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        """
        Create a new group.
        """
        serializer = GroupCreateSerializer(data=request.data)
        if serializer.is_valid():
            group = serializer.save(created_by=request.user)
            group.admins.add(request.user)
            group.members.add(request.user)
            GroupMember.objects.create(group=group, user=request.user, role='admin')

            return Response({
                'message': 'Group created successfully.',
                'group': {
                    'id': group.id,
                    'name': group.name,
                    'admins': [UserDetailSerializer(user).data for user in group.admins.all()],
                    'members': [UserDetailSerializer(user).data for user in group.members.all()],
                }
            }, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


    def get(self, request, group_id=None, *args, **kwargs):
        """
        Retrieve details of a specific group or all groups.
        """
        if group_id:
            group = get_object_or_404(Group, id=group_id)
            serializer = GroupCreateSerializer(group)
            return Response(serializer.data, status=status.HTTP_200_OK)

        groups = Group.objects.filter(members=request.user)
        serializer = GroupCreateSerializer(groups, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


    def patch(self, request, group_id, *args, **kwargs):
        """
        Update group details, add members, or assign admins.
        """
        group = get_object_or_404(Group, id=group_id)

        if request.user not in group.admins.all():
            return Response({'error': 'You do not have permission to update this group.'}, status=status.HTTP_403_FORBIDDEN)

        group.name = request.data.get('name', group.name)
        if 'group_pic' in request.FILES:
            group.group_pic = request.FILES['group_pic']
        group.save()

        return Response({
            'message': 'Group updated successfully.',
            'group': {
                'id': group.id,
                'name': group.name,
            }
        }, status=status.HTTP_200_OK)

    def delete(self, request, group_id, *args, **kwargs):
        """
        Delete a group.
        """
        group = get_object_or_404(Group, id=group_id)

        if request.user != group.created_by:
            return Response({'error': 'You do not have permission to delete this group.'}, status=status.HTTP_403_FORBIDDEN)

        group.delete()
        return Response({'message': 'Group deleted successfully.'}, status=status.HTTP_204_NO_CONTENT)


class GroupMemberAPIView(APIView):
    """
    API for managing group members.
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, group_id, *args, **kwargs):
        """
        Add a member to a group.
        """
        group = get_object_or_404(Group, id=group_id)

        if request.user not in group.admins.all():
            return Response({'error': 'You do not have permission to add members to this group.'}, status=status.HTTP_403_FORBIDDEN)

        user_id = request.data.get('user_id')
        role = request.data.get('role', 'member')

        user = get_object_or_404(User, id=user_id)

        group_member = GroupMember.objects.create(group=group, user=user, role=role)
        group.members.add(user)

        if role == 'admin':
            group.admins.add(user)

        return Response({'message': 'Member added successfully.'}, status=status.HTTP_201_CREATED)

    def delete(self, request, group_id, member_id, *args, **kwargs):
        """
        Remove a member from a group.
        """
        group = get_object_or_404(Group, id=group_id)

        if request.user not in group.admins.all():
            return Response({'error': 'You do not have permission to remove members from this group.'}, status=status.HTTP_403_FORBIDDEN)

        member = get_object_or_404(GroupMember, group=group, user__id=member_id)
        group.members.remove(member.user)

        if member.user in group.admins.all():
            group.admins.remove(member.user)

        member.delete()

        return Response({'message': 'Member removed successfully.'}, status=status.HTTP_204_NO_CONTENT)

    def patch(self, request, group_id, member_id, *args, **kwargs):
        """
        Update the role of a group member.
        """
        group = get_object_or_404(Group, id=group_id)

        if request.user not in group.admins.all():
            return Response({'error': 'You do not have permission to update member roles in this group.'}, status=status.HTTP_403_FORBIDDEN)

        role = request.data.get('role')
        if role not in ['member', 'admin']:
            return Response({'error': 'Invalid role.'}, status=status.HTTP_400_BAD_REQUEST)

        member = get_object_or_404(GroupMember, group=group, user__id=member_id)
        
        member.role = role
        member.save()

        if role == 'admin':
            group.admins.add(member.user)
        else:
            group.admins.remove(member.user)

        return Response({'message': 'Member role updated successfully.'}, status=status.HTTP_200_OK)
    

class SaveFaceEncodingView(APIView):
    def post(self, request, user_id):
        serializer = VideoUploadSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)

        video = serializer.validated_data['video']
        fastapi_url = "http://127.0.0.1:8002/video-to-encoding"
        files = {'video': video.file}
        try:
            response = requests.post(fastapi_url, files=files)
            response.raise_for_status()
        except requests.RequestException as e:
            return Response({"error": "Failed to connect to FastAPI.", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        data = response.json()
        face_encodings = data.get("face_encodings")
        if not face_encodings:
            return Response({"error": "No face encodings returned by FastAPI."}, status=status.HTTP_400_BAD_REQUEST)
        
        # media_root = 'media/face_encodings'
        media_root = os.path.join(settings.BASE_DIR, 'media')  # Get the actual base directory for media
        face_encodings_dir = os.path.join(media_root, 'face_encodings')

        # Ensure the directories exist
        os.makedirs(face_encodings_dir, exist_ok=True)


        pkl_filename = f"{user.id}_face_encoding.pkl"
        pkl_filepath = os.path.join(face_encodings_dir, pkl_filename)

        with open(pkl_filepath, 'wb') as pkl_file:
            pickle.dump(face_encodings, pkl_file)

        if user.face_encoding_file:
            user.face_encoding_file.delete()

        with open(pkl_filepath, 'rb') as pkl_file:
            user.face_encoding_file.save(pkl_filename, ContentFile(pkl_file.read()))

        os.remove(pkl_filepath)
        user.is_active = True
        user.save()

        return Response({"message": "Face encoding saved successfully."}, status=status.HTTP_200_OK)
    

class VerifyFaceView(APIView):
    def post(self, request, user_id):
        serializer = VerifyFaceSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)
       
        image = serializer.validated_data['image']

        if not user.face_encoding_file:
            return Response({"error": "User's face encoding file is missing."}, status=status.HTTP_404_NOT_FOUND)

        pkl_path = os.path.join(settings.MEDIA_ROOT, user.face_encoding_file.name)
        print(pkl_path)

        files = {
            'encodings_file': open(pkl_path, 'rb'),
            'auth_image': image
        }

        fastapi_url = "http://127.0.0.1:8002/verify-face"
        try:
            response = requests.post(fastapi_url, files=files)
            response.raise_for_status()
        except requests.RequestException as e:
            return Response({"error": "Failed to connect to FastAPI.", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        data = response.json()
        if "is_match" in data:
            
            if data["is_match"]:
                # return Response({"result": True}, status=status.HTTP_200_OK)
                refresh = RefreshToken.for_user(user)
                return Response({
                        'refresh': str(refresh),
                        'access': str(refresh.access_token),
                }, status=status.HTTP_200_OK)
            else:
                return Response({"message": "Face Authentication Failed. Try again.."}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "something went to wrong..."}, status=status.HTTP_400_BAD_REQUEST)
        

class CreateSubscriptionAPIView(APIView):
    def post(self, request,user_id):
        # email = request.data.get("email")
        payment_method_id = request.data.get("payment_method_id")
        price_id = request.data.get("price_id")

        if not payment_method_id or not price_id:
            return Response({"detail": "Missing required fields"}, status=status.HTTP_400_BAD_REQUEST)
        
        user = get_object_or_404(User, id=user_id)
        
        customer = create_stripe_customer(user.email, payment_method_id)
        
        subscription = create_subscription(customer.id, price_id)
        
        subscription_obj = Subscription.objects.create(
            user=user,
            stripe_customer_id=customer.id,
            stripe_subscription_id=subscription.id,
            is_active=True
        )

        serializer = SubscriptionSerializer(subscription_obj)
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class CancelSubscriptionAPIView(APIView):
    def post(self, request, user_id):
        subscription = get_object_or_404(Subscription, user_id=user_id, is_active=True)
        
        cancel_subscription(subscription.stripe_subscription_id)
        
        subscription.is_active = False
        subscription.save()
        
        return Response({"detail": "Subscription cancelled successfully"}, status=status.HTTP_200_OK)


class MessageListView(ListAPIView):
    """
    API view to retrieve messages.
    Supports filtering by sender, receiver, or group.
    """
    serializer_class = MessageSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Message.objects.all()


class ContinuousRetraining(APIView):
    def post(self, request):
        try:
            model_path = request.data.get('model_path', '../models/model.pkl')
            retrain_interval = int(request.data.get('retrain_interval', 10))
            max_minutes = int(request.data.get('max_minutes', 60))
            last_24_hours = timezone.now() - timedelta(hours=24)
            messages = Message.objects.filter(timestamp__gte=last_24_hours).values(
                "id",
                "sender__email",
                "receiver__email",
                "group__name",
                "content",
                "timestamp",
                "is_read"
            )
            messages_list = []
            for msg in messages:
                msg["timestamp"] = msg["timestamp"].isoformat()  
                msg["content"] = msg["content"].strip() if msg["content"] else ""  
                messages_list.append(msg)
            # print(f"Messages to be sent: {messages_list}")
            payload = {
                "model_path": model_path,
                "retrain_interval": retrain_interval,
                "max_minutes": max_minutes,
                "messages": messages_list 
            }
            timeout = httpx.Timeout(90.0)

            response = httpx.post(f"{FASTAPI_URL}/continuous-retraining", json=payload, timeout=timeout)

            if response.status_code == 200:
                return Response(response.json(), status=status.HTTP_200_OK)
            else:
                return Response(
                    {"error": response.json().get("detail", "Failed to perform continuous retraining")},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(["POST"])
def save_flagged_messages(request):
    try:
        flagged_messages = request.data.get("flagged_messages", [])

        for flagged in flagged_messages:
            message_id = flagged.get("id")
            message = Message.objects.filter(id=message_id).first()

            if message:
                Flag.objects.create(message=message, created_at=timezone.now())

        return Response({"message": "Flagged messages saved successfully."}, status=status.HTTP_201_CREATED)

    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    

class FlaggedUserListAPIView(APIView):
    permission_classes = [permissions.IsAdminUser]

    def get(self, request):
        flagged_users = User.objects.filter(flag_count__gt=0)
        serializer = AdminUserSerializer(flagged_users, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class AnalyticsAPIView(APIView):
    permission_classes = [permissions.IsAdminUser]

    def get(self, request):
        active_users = User.objects.filter(is_active=True).count()
        blocked_users = User.objects.filter(is_blocked=True).count()
        flagged_count = Flag.objects.count()  
        data = {
            "active_users": active_users,
            "blocked_users": blocked_users,
            "flagged_content": flagged_count,
        }
        return Response(data, status=status.HTTP_200_OK)


class UserListCreateAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        if not request.user.is_staff:
            return Response({'detail': 'Only admins can view all users.'}, status=status.HTTP_403_FORBIDDEN)
        users = User.objects.all()
        serializer = UserSerializer(users, many=True)
        return Response(serializer.data)

    def post(self, request):
        if not request.user.is_staff:
            return Response({'detail': 'Only admins can create users.'}, status=status.HTTP_403_FORBIDDEN)
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    




