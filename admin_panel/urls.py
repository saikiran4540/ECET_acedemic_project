from django.urls import path
from . import views

app_name = 'admin_panel'

urlpatterns = [
    path('dashboard/', views.admin_dashboard, name='dashboard'),
    path('users/', views.manage_users, name='manage_users'),
    path('users/toggle/<int:user_id>/', views.toggle_user_status, name='toggle_user_status'),
    path('datasets/', views.manage_datasets, name='manage_datasets'),
    path('datasets/upload/', views.upload_dataset, name='upload_dataset'),
    path('datasets/train/<int:dataset_id>/', views.train_model, name='train_model'),
    path('performance/', views.model_performance, name='model_performance'),
    path('logs/', views.system_logs, name='system_logs'),
]
