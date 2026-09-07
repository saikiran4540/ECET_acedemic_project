from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.conf import settings
from detection.models import DetectionHistory
from .models import Report
import csv
from datetime import datetime

@login_required
def generate_report(request):
    """Generate user activity report"""
    if request.method == 'POST':
        report_type = request.POST.get('report_type')
        
        # Create CSV response
        response = HttpResponse(content_type='text/csv')
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        response['Content-Disposition'] = f'attachment; filename="report_{timestamp}.csv"'
        
        writer = csv.writer(response)
        
        if report_type == 'detection':
            # Detection history report
            detections = DetectionHistory.objects.filter(user=request.user)
            
            writer.writerow(['Phishing Detection History Report'])
            writer.writerow(['Generated:', datetime.now().strftime('%Y-%m-%d %H:%M:%S')])
            writer.writerow(['User:', request.user.username])
            writer.writerow([])
            writer.writerow(['ID', 'Type', 'Input', 'Result', 'Confidence', 'Date'])
            
            for detection in detections:
                writer.writerow([
                    detection.id,
                    detection.get_detection_type_display(),
                    detection.input_text,
                    detection.get_result_display(),
                    f'{detection.confidence_score * 100:.2f}%',
                    detection.created_at.strftime('%Y-%m-%d %H:%M:%S')
                ])
        
        return response
    
    return render(request, 'reports/generate_report.html')
