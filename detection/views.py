from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import JsonResponse, HttpResponse
from django.conf import settings
from django.core.paginator import Paginator
from .models import DetectionHistory, PhishingFeature
from .utils import extract_url_features, extract_email_features, extract_features, detect_input_type, get_feature_importance_explanation, is_valid_email, is_valid_url
import joblib
import json
import os
from datetime import datetime
import sys
import logging

# Configure logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# Add ML models to path
sys.path.append(str(settings.BASE_DIR / 'ml_models'))
from phishing_detector import HybridPhishingDetector

# Load ML model once
detector = None

def load_detector():
    """Load ML model"""
    global detector
    if detector is None:
        try:
            detector = HybridPhishingDetector()
            model_path = settings.ML_MODELS_DIR / 'trained'
            detector.load_models(str(model_path))
            print("✓ ML Model loaded successfully")
        except Exception as e:
            print(f"✗ Error loading ML model: {e}")
            detector = None
    return detector

@login_required
def dashboard_view(request):
    """User dashboard"""
    # Get user statistics
    total_scans = DetectionHistory.objects.filter(user=request.user).count()
    phishing_detected = DetectionHistory.objects.filter(
        user=request.user, 
        result='phishing'
    ).count()
    legitimate_detected = DetectionHistory.objects.filter(
        user=request.user, 
        result='legitimate'
    ).count()
    
    # Recent detections
    recent_detections = DetectionHistory.objects.filter(
        user=request.user
    )[:5]
    
    context = {
        'total_scans': total_scans,
        'phishing_detected': phishing_detected,
        'legitimate_detected': legitimate_detected,
        'recent_detections': recent_detections,
    }
    return render(request, 'detection/dashboard.html', context)

@login_required
def analyze_view(request):
    """Analyze URL or email for phishing"""
    if request.method == 'POST':
        detection_type = request.POST.get('detection_type', 'auto')
        input_text = request.POST.get('input_text', '').strip()
        
        if not input_text:
            messages.error(request, 'Please enter a URL or email to analyze')
            return redirect('detection:analyze')
        
        try:
            # Auto-detect input type if not specified
            if detection_type == 'auto':
                detected_type = detect_input_type(input_text)
            else:
                detected_type = detection_type
            
            # Validate format
            if detected_type == 'email' and not is_valid_email(input_text):
                messages.error(request, 'Please enter a valid email address')
                return redirect('detection:analyze')
            elif detected_type == 'url' and not is_valid_url(input_text):
                # Try to be lenient with URLs (some might not have http)
                if not (input_text.startswith('www.') or '.' in input_text):
                    messages.error(request, 'Please enter a valid URL')
                    return redirect('detection:analyze')
            
            # Extract features
            if detected_type == 'email':
                features = extract_email_features(input_text)
            else:
                features = extract_url_features(input_text)
            
            # Load detector
            detector = load_detector()
            if detector is None:
                messages.error(request, 'ML Model not available. Please contact administrator.')
                return redirect('detection:analyze')
            
            # Get prediction
            result = detector.predict(features)
            logger.info(f"Prediction Result: {result['prediction']}, Confidence: {result['confidence']:.4f}")
            
            # Convert confidence to 0-100 scale for storage
            confidence_percentage = result['confidence'] * 100
            
            # Get feature importance
            important_features = get_feature_importance_explanation(features)
            
            # Save to database
            detection = DetectionHistory.objects.create(
                user=request.user,
                detection_type=detected_type,
                input_text=input_text,
                result=result['prediction'],
                confidence_score=confidence_percentage,  # Store as 0-100 instead of 0-1
                features_used=features
            )
            logger.info(f"Detection saved: ID={detection.id}, Result={detection.result}")
            
            # Save important features
            for feature_name, feature_value, score in important_features:
                PhishingFeature.objects.create(
                    detection=detection,
                    feature_name=feature_name,
                    feature_value=feature_value,
                    importance=score
                )
            
            # Redirect to results
            return redirect('detection:result', detection_id=detection.id)
            
        except Exception as e:
            logger.error(f"Error during analysis: {str(e)}", exc_info=True)
            messages.error(request, f'Error during analysis: {str(e)}')
            return redirect('detection:analyze')
    
    return render(request, 'detection/analyze.html')

@login_required
def result_view(request, detection_id):
    """View detection result"""
    detection = get_object_or_404(
        DetectionHistory, 
        id=detection_id, 
        user=request.user
    )
    
    # Get important features
    features = detection.features.all()
    
    context = {
        'detection': detection,
        'features': features,
    }
    return render(request, 'detection/result.html', context)

@login_required
def history_view(request):
    """View detection history"""
    detections = DetectionHistory.objects.filter(user=request.user)
    
    # Filter by type
    filter_type = request.GET.get('type', 'all')
    if filter_type != 'all':
        detections = detections.filter(detection_type=filter_type)
    
    # Filter by result
    filter_result = request.GET.get('result', 'all')
    if filter_result != 'all':
        detections = detections.filter(result=filter_result)
    
    # Pagination
    paginator = Paginator(detections, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'page_obj': page_obj,
        'filter_type': filter_type,
        'filter_result': filter_result,
    }
    return render(request, 'detection/history.html', context)

@login_required
def delete_detection(request, detection_id):
    """Delete detection record"""
    detection = get_object_or_404(
        DetectionHistory, 
        id=detection_id, 
        user=request.user
    )
    detection.delete()
    messages.success(request, 'Detection record deleted')
    return redirect('detection:history')

@login_required
def download_report(request, detection_id):
    """Download detection report as CSV"""
    detection = get_object_or_404(
        DetectionHistory, 
        id=detection_id, 
        user=request.user
    )
    
    # Create CSV response
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="detection_report_{detection.id}.csv"'
    
    import csv
    writer = csv.writer(response)
    
    # Write header
    writer.writerow(['Phishing Detection Report'])
    writer.writerow([])
    writer.writerow(['Field', 'Value'])
    writer.writerow(['Detection ID', detection.id])
    writer.writerow(['Type', detection.get_detection_type_display()])
    writer.writerow(['Input', detection.input_text])
    writer.writerow(['Result', detection.get_result_display()])
    writer.writerow(['Confidence', f'{detection.confidence_score:.2f}%'])
    writer.writerow(['Date', detection.created_at.strftime('%Y-%m-%d %H:%M:%S')])
    writer.writerow([])
    
    # Write features
    writer.writerow(['Important Features'])
    writer.writerow(['Feature Name', 'Value', 'Importance'])
    for feature in detection.features.all():
        writer.writerow([feature.feature_name, feature.feature_value, feature.importance])
    
    return response
