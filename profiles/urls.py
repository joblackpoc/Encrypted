from django.urls import path
from . import views

urlpatterns = [
    path('', views.welcome, name='welcome'),
    path('register/', views.register, name='register'),
    path('login/', views.login, name='login'),
    path('logout/', views.login, name='logout'),
    path('verify_otp/', views.verify_otp, name='verify_otp'),
    path('profile/', views.profile_detail, name='profile_detail'),
    path('profile/update/', views.update_profile, name='update_profile'),
    path('profile/delete/', views.profile_delete, name='profile_delete'),
    path('profile/delete/confirm/', views.profile_confirm_delete, name='profile_confirm_delete'),
    path('profile_detail_pdf/', views.profile_detail_pdf, name='profile_detail_pdf'),
]
