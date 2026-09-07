import json
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib import messages
from django.http import JsonResponse
from django.conf import settings
from django.core.paginator import Paginator
from django.db.models import Count
from .models import Dataset, ModelTraining, SystemLog
from detection.models import DetectionHistory
from django.contrib.auth.models import User
import os
import pandas as pd
import sys
from datetime import datetime, timedelta

sys.path.append(str(settings.BASE_DIR / 'ml_models'))
from phishing_detector import HybridPhishingDetector

def is_admin(user):
    """Check if user is admin"""
    return user.is_staff or user.is_superuser

@login_required
@user_passes_test(is_admin)
def admin_dashboard(request):
    """Admin dashboard"""
    # Statistics
    total_users = User.objects.count()
    total_detections = DetectionHistory.objects.count()
    phishing_detected = DetectionHistory.objects.filter(result='phishing').count()
    legitimate_detected = DetectionHistory.objects.filter(result='legitimate').count()
    total_datasets = Dataset.objects.count()
    
    # Recent activities
    recent_logs = SystemLog.objects.all()[:10]
    recent_trainings = ModelTraining.objects.all()[:5]
    
    # Chart data - detections per day (last 7 days)
    today = datetime.now().date()
    dates = [(today - timedelta(days=i)).strftime('%Y-%m-%d') for i in range(6, -1, -1)]
    detection_counts = []
    
    for date_str in dates:
        date_obj = datetime.strptime(date_str, '%Y-%m-%d').date()
        count = DetectionHistory.objects.filter(
            created_at__date=date_obj
        ).count()
        detection_counts.append(count)
    
    context = {
        'total_users': total_users,
        'total_detections': total_detections,
        'phishing_detected': phishing_detected,
        'legitimate_detected': legitimate_detected,
        'total_datasets': total_datasets,
        'recent_logs': recent_logs,
        'recent_trainings': recent_trainings,
        'chart_dates': json.dumps(dates),
        'chart_counts': json.dumps(detection_counts),
    }
    return render(request, 'admin_panel/dashboard.html', context)

@login_required
@user_passes_test(is_admin)
def manage_users(request):
    """Manage users"""
    users = User.objects.all().order_by('-date_joined')
    
    # Pagination
    paginator = Paginator(users, 15)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'page_obj': page_obj,
    }
    return render(request, 'admin_panel/manage_users.html', context)

@login_required
@user_passes_test(is_admin)
def toggle_user_status(request, user_id):
    """Activate/deactivate user"""
    user = get_object_or_404(User, id=user_id)
    user.is_active = not user.is_active
    user.save()
    
    status = 'activated' if user.is_active else 'deactivated'
    messages.success(request, f'User {user.username} {status}')
    
    # Log activity
    SystemLog.objects.create(
        log_type='info',
        message=f'User {user.username} {status} by {request.user.username}',
        user=request.user,
        ip_address=request.META.get('REMOTE_ADDR')
    )
    
    return redirect('admin_panel:manage_users')

@login_required
@user_passes_test(is_admin)
def manage_datasets(request):
    """Manage datasets"""
    datasets = Dataset.objects.all()
    
    context = {
        'datasets': datasets,
    }
    return render(request, 'admin_panel/manage_datasets.html', context)

@login_required
@user_passes_test(is_admin)
def upload_dataset(request):
    """Upload new dataset"""
    if request.method == 'POST':
        name = request.POST.get('name')
        description = request.POST.get('description')
        file = request.FILES.get('file')
        
        if not file:
            messages.error(request, 'Please select a file')
            return redirect('admin_panel:upload_dataset')
        
        try:
            # Read and validate CSV
            df = pd.read_csv(file)
            
            if 'label' not in df.columns:
                messages.error(request, 'Dataset must contain a "label" column')
                return redirect('admin_panel:upload_dataset')
            
            total_samples = len(df)
            phishing_samples = len(df[df['label'] == 1])
            legitimate_samples = len(df[df['label'] == 0])
            
            # Save dataset
            dataset = Dataset.objects.create(
                name=name,
                description=description,
                file_path=file,
                total_samples=total_samples,
                phishing_samples=phishing_samples,
                legitimate_samples=legitimate_samples,
                uploaded_by=request.user
            )
            
            messages.success(request, f'Dataset "{name}" uploaded successfully')
            
            # Log activity
            SystemLog.objects.create(
                log_type='success',
                message=f'Dataset "{name}" uploaded by {request.user.username}',
                user=request.user,
                ip_address=request.META.get('REMOTE_ADDR')
            )
            
            return redirect('admin_panel:manage_datasets')
            
        except Exception as e:
            messages.error(request, f'Error uploading dataset: {str(e)}')
            return redirect('admin_panel:upload_dataset')
    
    return render(request, 'admin_panel/upload_dataset.html')

@login_required
@user_passes_test(is_admin)
def train_model(request, dataset_id):
    """Train ML model with dataset"""
    dataset = get_object_or_404(Dataset, id=dataset_id)
    
    try:
        # Create training record
        training = ModelTraining.objects.create(
            dataset=dataset,
            model_name='Hybrid Stacked Ensemble',
            status='training',
            started_by=request.user
        )
        
        # Train model in background (in production, use Celery)
        detector = HybridPhishingDetector()
        
        file_path = dataset.file_path.path
        history = detector.train_full_model(file_path, apply_smote=True, k_folds=5)
        
        # Save models
        model_dir = settings.ML_MODELS_DIR / 'trained'
        detector.save_models(str(model_dir))
        
        # Update training record
        training.status = 'completed'
        training.accuracy = history['stacked_metrics']['accuracy']
        training.precision = history['stacked_metrics']['precision']
        training.recall = history['stacked_metrics']['recall']
        training.f1_score = history['stacked_metrics']['f1_score']
        training.model_file_path = str(model_dir)
        training.completed_at = datetime.now()
        training.parameters = history
        training.save()
        
        messages.success(request, f'Model trained successfully! Accuracy: {training.accuracy:.4f}')
        
        # Log activity
        SystemLog.objects.create(
            log_type='success',
            message=f'Model trained with dataset "{dataset.name}" by {request.user.username}',
            user=request.user,
            ip_address=request.META.get('REMOTE_ADDR')
        )
        
    except Exception as e:
        training.status = 'failed'
        training.error_message = str(e)
        training.save()
        
        messages.error(request, f'Training failed: {str(e)}')
        
        # Log error
        SystemLog.objects.create(
            log_type='error',
            message=f'Model training failed: {str(e)}',
            user=request.user,
            ip_address=request.META.get('REMOTE_ADDR')
        )
    
    return redirect('admin_panel:model_performance')

@login_required
@user_passes_test(is_admin)
def model_performance(request):
    """View model performance metrics"""
    trainings = ModelTraining.objects.all()
    
    context = {
        'trainings': trainings,
    }
    return render(request, 'admin_panel/model_performance.html', context)

@login_required
@user_passes_test(is_admin)
def system_logs(request):
    """View system logs"""
    logs = SystemLog.objects.all()
    
    # Filter by type
    log_type = request.GET.get('type', 'all')
    if log_type != 'all':
        logs = logs.filter(log_type=log_type)
    
    # Pagination
    paginator = Paginator(logs, 20)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'page_obj': page_obj,
        'log_type': log_type,
    }
    return render(request, 'admin_panel/system_logs.html', context)
