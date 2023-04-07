from django.urls import path
from . import views

urlpatterns = [
    path('', views.welcome, name='welcome'),
    path('register/', views.register, name='register'),
    path('login/', views.login, name='login'),
    path('verify_otp/', views.verify_otp, name='verify_otp'),
    path('profile_detail/', views.profile_detail, name='profile_detail'),
    path('update_profile/', views.update_profile, name='update_profile'),
    path('profile_list/', views.profile_list, name='profile_list'),
    path('delete_profile/', views.delete_profile, name='delete_profile'),
    path('profile_detail_pdf/', views.profile_detail_pdf, name='profile_detail_pdf'),
]
