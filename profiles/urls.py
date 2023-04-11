from django.urls import path
from . import views

urlpatterns = [
    path('', views.welcome, name='welcome'),
    path('register/', views.register, name='register'),
    path('login/', views.login, name='login'),
    path('logout/', views.login, name='logout'),
    path('verify-otp/', views.verify_otp, name='verify_otp'),
    path('profile-detail/<int:pk>', views.profile_detail, name='profile_detail'),
    path('profile-update/<int:pk>/', views.profile_update, name='profile_update'),
    path('profile-delete/<int:pk>/', views.profile_delete, name='profile_delete'),
    path('profile-confirm-delete/<int:pk>/', views.profile_confirm_delete, name='profile_confirm_delete'),

]
