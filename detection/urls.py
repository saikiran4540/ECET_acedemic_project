from django.urls import path
from . import views

app_name = 'detection'

urlpatterns = [
    path('dashboard/', views.dashboard_view, name='dashboard'),
    path('analyze/', views.analyze_view, name='analyze'),
    path('result/<int:detection_id>/', views.result_view, name='result'),
    path('history/', views.history_view, name='history'),
    path('delete/<int:detection_id>/', views.delete_detection, name='delete'),
    path('download/<int:detection_id>/', views.download_report, name='download_report'),
]
