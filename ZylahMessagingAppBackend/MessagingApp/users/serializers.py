from rest_framework import serializers
from .models import User,Message,Group,Subscription,Flag
from django.contrib.auth import get_user_model


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=8)

    class Meta:
        model = User
        fields = "__all__"

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)
    

class UserUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'phone_number', 'profile_pic']
        extra_kwargs = {
            'first_name': {'required': False},
            'last_name': {'required': False},
            'phone_number': {'required': False},
            'profile_pic': {'required': False},
        }


class UserDetailSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'first_name', 'last_name', 'email', 'phone_number', 'profile_pic', 'face_encoding_file','created_at', 'updated_at']


class SendOtpSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, email):
        if not User.objects.filter(email=email).exists():
            raise serializers.ValidationError("No user is associated with this email.")
        return email
    
    
class ChangePasswordWithOtpSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6)
    new_password = serializers.CharField(write_only=True)


class AdminChangePasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()
    new_password = serializers.CharField(write_only=True)

    def validate(self, data):
        """ Ensure that the user exists before proceeding """
        email = data.get('email')
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError({"email": "User with this email does not exist."})
        return data
    

class MessageSerializer(serializers.ModelSerializer):
    class Meta:
        model = Message
        fields = ['id', 'sender', 'receiver','group', 'content', 'timestamp']


class GroupCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating a group."""
    class Meta:
        model = Group
        fields = ['id','name', 'group_pic', 'members', 'admins','created_at']
        extra_kwargs = {
            'members': {'required': False},
            'admins': {'required': False},
        }


class VideoUploadSerializer(serializers.Serializer):
    video = serializers.FileField(required=True)  


class VerifyFaceSerializer(serializers.Serializer):
    image = serializers.ImageField(required=True)

class SubscriptionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Subscription
        fields = ['user', 'stripe_customer_id', 'stripe_subscription_id', 'is_active']


class FlagSerializer(serializers.ModelSerializer):
    """Serializer for the Flag model."""

    message = serializers.PrimaryKeyRelatedField(queryset=Message.objects.all())
    created_at = serializers.DateTimeField(read_only=True)
    reviewed = serializers.BooleanField()

    class Meta:
        model = Flag
        fields = ['id', 'message', 'created_at', 'reviewed']

    def update(self, instance, validated_data):
        """Custom update method for setting reviewed flag."""
        instance.reviewed = validated_data.get('reviewed', instance.reviewed)
        instance.save()
        return instance



User = get_user_model()

class AdminUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'first_name', 'last_name', 'email', 'phone_number', 'profile_pic', 
                  'is_active', 'is_staff', 'is_blocked']
        read_only_fields = ['id']

    def create(self, validated_data):
        password = validated_data.pop('password', None)
        user = User.objects.create(**validated_data)
        if password:
            user.set_password(password)
        user.save()
        return user

    def update(self, instance, validated_data):
        password = validated_data.pop('password', None)
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        if password:
            instance.set_password(password)
        instance.save()
        return instance


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'first_name', 'last_name', 'email', 'phone_number', 'profile_pic', 'face_encoding_file', 'is_active', 'is_staff', 'is_blocked', 'flag_count']
        read_only_fields = ['is_active', 'is_staff', 'is_blocked', 'flag_count']
