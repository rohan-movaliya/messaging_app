from django.urls import path
from .views import RegisterView,LoginView,PasswordResetView,GroupAPIView,GroupMemberAPIView,SaveFaceEncodingView,VerifyFaceView,CreateSubscriptionAPIView,CancelSubscriptionAPIView,MessageListView,ContinuousRetraining,save_flagged_messages,FlaggedUserListAPIView,AnalyticsAPIView,UserListCreateAPIView,UserDetailAPIView,AdminChangePasswordView
urlpatterns = [
    path("register/", RegisterView.as_view(), name="register"),
    path("login/", LoginView.as_view(), name="register"),
    path('users/', UserListCreateAPIView.as_view(), name='user-list-create'),
    path('users/<int:pk>/', UserDetailAPIView.as_view(), name='user-detail'),
    path('otp/password-reset/', PasswordResetView.as_view(), name='send-password-reset'),
    path('send/password-reset/', PasswordResetView.as_view(), name='password-reset'),
    path('admin-change-password/', AdminChangePasswordView.as_view(), name='admin-change-password'),
    path("group/create/", GroupAPIView.as_view(), name="group-create"),
    path("group/create/<int:group_id>/", GroupAPIView.as_view(), name="group-create"),
    path("group/add/<int:group_id>/", GroupMemberAPIView.as_view(), name="group-member"),
    path("group/add/<int:group_id>/<int:member_id>/",GroupMemberAPIView.as_view(), name="group-member"),
    path('save-face-encoding/<int:user_id>/', SaveFaceEncodingView.as_view(), name='save_face_encoding'),
    path('verify-face/<int:user_id>/', VerifyFaceView.as_view(), name='verify_face'),
    path('create-subscription/<int:user_id>/', CreateSubscriptionAPIView.as_view(), name='create_subscription'),
    path('cancel-subscription/<int:user_id>/', CancelSubscriptionAPIView.as_view(), name='cancel_subscription'),
    path('messages/', MessageListView.as_view(), name='message-list'),
    path('continuous-retraining/', ContinuousRetraining.as_view(), name='continuous_retraining'),
    path("save-flagged-messages/", save_flagged_messages, name="save_flagged_messages"),
    path('admin/flagged-users/', FlaggedUserListAPIView.as_view(), name='flagged-user-list'),
    path('admin/analytics/', AnalyticsAPIView.as_view(), name='admin-analytics'),
]