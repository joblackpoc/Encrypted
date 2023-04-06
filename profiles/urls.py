from django.urls import path
from . import views

app_name = 'profiles'

urlpatterns = [
    path('create_profile/', views.create_profile, name='create_profile'),
    path('update_profile/<int:pk>/', views.update_profile, name='update_profile'),
    path('login/', views.login_view, name='login'),
    path('verify_otp/', views.verify_otp, name='verify_otp'),
    path('profile_detail/<int:pk>/', views.profile_detail, name='profile_detail'),
    path('delete_profile/<int:pk>/', views.delete_profile, name='delete_profile'),
]
