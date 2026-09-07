from django.db import models
from django.contrib.auth.models import User

class DetectionHistory(models.Model):
    DETECTION_TYPES = [
        ('url', 'URL'),
        ('email', 'Email'),
    ]
    
    RESULT_TYPES = [
        ('phishing', 'Phishing'),
        ('legitimate', 'Legitimate'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='detections')
    detection_type = models.CharField(max_length=10, choices=DETECTION_TYPES)
    input_text = models.TextField()
    result = models.CharField(max_length=20, choices=RESULT_TYPES)
    confidence_score = models.FloatField()
    features_used = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.user.username} - {self.detection_type} - {self.result}"
    
    class Meta:
        db_table = 'detection_history'
        ordering = ['-created_at']

class PhishingFeature(models.Model):
    detection = models.ForeignKey(DetectionHistory, on_delete=models.CASCADE, related_name='features')
    feature_name = models.CharField(max_length=100)
    feature_value = models.FloatField()
    importance = models.FloatField(null=True, blank=True)
    
    def __str__(self):
        return f"{self.feature_name}: {self.feature_value}"
    
    class Meta:
        db_table = 'phishing_features'
