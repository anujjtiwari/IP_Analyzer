from django.urls import path
from . import views

urlpatterns = [
    path('user_sign_up/', views.user_sign_up.as_view(), name='User Sign Up API'),
    path('user_sign_in/', views.user_sign_in.as_view(), name='User Sign In API'),
    path('user_sign_out/', views.user_sign_out.as_view(), name='User Sign Out API'),
    path('forgot_password/', views.forgot_password.as_view(), name='Forgot Password API'),
    path('set_password/', views.set_password.as_view(), name='Set Password API'),
    path('update_name/', views.update_name.as_view(), name='Update User Name API'),
    path('update_password/', views.update_password.as_view(), name='Update User Password API'),
    path('update_email/', views.update_email.as_view(), name='Generate Token For Email Update API'),
    path('set_email/', views.set_email.as_view(), name='Set Email API'),
    path('is_admin/', views.is_admin.as_view(), name='Check Admin API'),
    path('check_sign_in_token/', views.check_sign_in_token.as_view(), name='Check Sign In API'),
    path('check_set_password_token/', views.check_set_password_token.as_view(), name='Check Set Password API'),
    path('otp_verify/', views.otp_verify.as_view(), name='OTP Verify Sign Up API'),
    path('resend_otp/', views.resend_otp.as_view(), name='OTP Resend API'),
    path('user_name/', views.user_name.as_view(), name='User Name API'),
    path('user_info/', views.user_info.as_view(), name='User Info API'),
    path('admin_name/', views.admin_name.as_view(), name='Admin Name API'),
    path('compute_results/', views.compute.as_view(), name='Compute Results API'),
    path('user_list/', views.user_list.as_view(), name='User List'),
    path('delete_user/', views.delete_user.as_view(), name='Delete User API'),
    path('lock_user/', views.lock_user.as_view(), name='Lock User API'),
    path('unlock_user/', views.unlock_user.as_view(), name='Unlock User API'),
    path('make_admin/', views.make_admin.as_view(), name='Make Admin API'),
    path('revoke_admin/', views.revoke_admin.as_view(), name='Revoke Admin API'),
]