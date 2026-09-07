from django.db import models
from django.contrib.auth.models import User

class Report(models.Model):
    REPORT_TYPES = [
        ('detection', 'Detection Report'),
        ('performance', 'Model Performance'),
        ('usage', 'System Usage'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='reports')
    report_type = models.CharField(max_length=20, choices=REPORT_TYPES)
    title = models.CharField(max_length=200)
    file_path = models.FileField(upload_to='reports/')
    generated_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.title} - {self.generated_at}"
    
    class Meta:
        db_table = 'reports'
        ordering = ['-generated_at']
