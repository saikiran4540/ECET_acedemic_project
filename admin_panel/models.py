from django.db import models
from django.contrib.auth.models import User

class Dataset(models.Model):
    name = models.CharField(max_length=200)
    description = models.TextField()
    file_path = models.FileField(upload_to='datasets/')
    total_samples = models.IntegerField(default=0)
    phishing_samples = models.IntegerField(default=0)
    legitimate_samples = models.IntegerField(default=0)
    uploaded_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)
    
    def __str__(self):
        return self.name
    
    class Meta:
        db_table = 'datasets'
        ordering = ['-uploaded_at']

class ModelTraining(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('training', 'Training'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]
    
    dataset = models.ForeignKey(Dataset, on_delete=models.CASCADE)
    model_name = models.CharField(max_length=100)
    accuracy = models.FloatField(null=True, blank=True)
    precision = models.FloatField(null=True, blank=True)
    recall = models.FloatField(null=True, blank=True)
    f1_score = models.FloatField(null=True, blank=True)
    training_time = models.FloatField(null=True, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    model_file_path = models.CharField(max_length=500, blank=True)
    parameters = models.JSONField(default=dict)
    started_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    started_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    error_message = models.TextField(blank=True)
    
    def __str__(self):
        return f"{self.model_name} - {self.status}"
    
    class Meta:
        db_table = 'model_training'
        ordering = ['-started_at']

class SystemLog(models.Model):
    LOG_TYPES = [
        ('info', 'Info'),
        ('warning', 'Warning'),
        ('error', 'Error'),
        ('success', 'Success'),
    ]
    
    log_type = models.CharField(max_length=20, choices=LOG_TYPES)
    message = models.TextField()
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.log_type.upper()} - {self.created_at}"
    
    class Meta:
        db_table = 'system_logs'
        ordering = ['-created_at']
