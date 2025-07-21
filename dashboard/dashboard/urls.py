"""
URL patterns for the dashboard app.
"""

from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('devices/', views.device_list, name='device_list'),
    path('devices/<str:device_id>/', views.device_detail, name='device_detail'),
    path('alerts/', views.alert_list, name='alert_list'),
    path('policies/', views.policy_list, name='policy_list'),
    path('policies/create/', views.policy_create, name='policy_create'),
    path('alerts/<int:alert_id>/resolve/', views.resolve_alert, name='resolve_alert'),
    path('tools/', views.security_tools_overview, name='security_tools_overview'),
    path('policies/<int:policy_id>/activate', views.policy_activate, name='policy_activate'),
    path('policies/recheck', views.policy_recheck, name='policy_recheck'),
    path('policies/<int:policy_id>/edit', views.policy_edit, name='policy_edit'),
    path('policies/<int:policy_id>/delete', views.policy_delete, name='policy_delete'),
    path('user-inventory/', views.user_inventory, name='user_inventory'),
    path('analytics/snapshots/', views.snapshot_trend_view, name='snapshot_trend_view')
] 