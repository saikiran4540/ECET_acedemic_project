from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib import messages
from django.http import JsonResponse
from .models import UserProfile

def register_view(request):
    """User registration"""
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        password2 = request.POST.get('password2')
        phone = request.POST.get('phone', '')
        
        # Validation
        if password != password2:
            messages.error(request, 'Passwords do not match')
            return redirect('accounts:register')
        
        if User.objects.filter(username=username).exists():
            messages.error(request, 'Username already exists')
            return redirect('accounts:register')
        
        if User.objects.filter(email=email).exists():
            messages.error(request, 'Email already registered')
            return redirect('accounts:register')
        
        # Create user
        user = User.objects.create_user(
            username=username,
            email=email,
            password=password
        )
        
        # Create profile
        UserProfile.objects.create(
            user=user,
            phone=phone
        )
        
        messages.success(request, 'Registration successful! Please login.')
        return redirect('accounts:login')
    
    return render(request, 'accounts/register.html')

def login_view(request):
    """User login"""
    if request.user.is_authenticated:
        return redirect('detection:dashboard')
    
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            login(request, user)
            messages.success(request, f'Welcome back, {user.username}!')
            
            # Redirect based on user type
            if user.is_staff or user.is_superuser:
                return redirect('admin_panel:dashboard')
            else:
                return redirect('detection:dashboard')
        else:
            messages.error(request, 'Invalid username or password')
            return redirect('accounts:login')
    
    return render(request, 'accounts/login.html')

@login_required
def logout_view(request):
    """User logout"""
    logout(request)
    messages.success(request, 'Logged out successfully')
    return redirect('accounts:login')

@login_required
def profile_view(request):
    """View and update user profile"""
    profile, created = UserProfile.objects.get_or_create(user=request.user)
    
    if request.method == 'POST':
        # Update user info
        request.user.first_name = request.POST.get('first_name', '')
        request.user.last_name = request.POST.get('last_name', '')
        request.user.email = request.POST.get('email', '')
        request.user.save()
        
        # Update profile
        profile.phone = request.POST.get('phone', '')
        profile.address = request.POST.get('address', '')
        profile.email_notifications = request.POST.get('email_notifications') == 'on'
        profile.save()
        
        messages.success(request, 'Profile updated successfully')
        return redirect('accounts:profile')
    
    context = {
        'user': request.user,
        'profile': profile
    }
    return render(request, 'accounts/profile.html', context)
