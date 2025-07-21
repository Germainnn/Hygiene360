"""
Views for the Hygiene360 dashboard app.
"""

import requests
import json
import logging
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.conf import settings
from django.http import HttpResponse, JsonResponse
from django.contrib import messages
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from django.utils.timezone import make_aware
from dateutil import parser
from datetime import datetime
from datetime import timedelta
from collections import defaultdict

# Create logger
logger = logging.getLogger(__name__)

# API URL
API_URL = settings.API_URL

def api_request(endpoint, method='GET', data=None):
    url = f"{API_URL}/{endpoint}"
    headers = {'Cache-Control': 'no-cache'}

    try:
        if method == 'GET':
            response = requests.get(url, headers=headers)
        elif method == 'POST':
            response = requests.post(url, json=data, headers=headers)
        elif method == 'PATCH':
            response = requests.patch(url, json=data, headers=headers)
        elif method == 'DELETE':
            response = requests.delete(url, headers=headers)
        else:
            raise ValueError(f"Unsupported HTTP method: {method}")

        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logger.error(f"API request error: {e}")
        return {'success': False, 'error': str(e)}

def home(request):
    """
    Home page view
    """
    return render(request, 'home.html')

@login_required
def dashboard(request):
    """
    Main dashboard view
    """
    # Get dashboard summary data
    summary = api_request('dashboard/summary')
    if not summary:
        messages.error(request, "Could not retrieve dashboard data from the API. Please try again later.")
        summary = {
            'device_stats': {'total': 0, 'compliant': 0, 'compliance_rate': 0},
            'alert_stats': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'total': 0},
            'security_score': {'average': 0},
            'security_features': {'antivirus_rate': 0, 'firewall_rate': 0, 'encryption_rate': 0}
        }
    
    tools_summary = api_request('dashboard/security-tools-summary')

    def top_tool(tools):
        return max(tools, key=lambda t: t["installed"]) if tools else None

    # get the API response
    tool_summary_data = api_request("dashboard/security-tools-summary")

    tools_summary = tool_summary_data.get("tools", {}) if tool_summary_data else {}

    top_tools = {
        "edr": top_tool(tools_summary.get("edr", [])),
        "dlp": top_tool(tools_summary.get("dlp", [])),
        "antivirus": top_tool(tools_summary.get("antivirus", [])),
    }

    # Get recent alerts
    alerts = api_request('alerts')
    if alerts:
        recent_alerts = alerts.get('alerts', [])[:5]  # Get latest 5 alerts
    else:
        recent_alerts = []
    
    # Get all devices
    devices = api_request('devices')
    if devices:
        device_list = devices.get('devices', [])
    else:
        device_list = []
    
    # Preprocess score buckets
    score_buckets = {
        '0-20': 0,
        '21-40': 0,
        '41-60': 0,
        '61-80': 0,
        '81-100': 0
    }

    for device in device_list:
        score = device.get('security_score', 0)
        if score <= 20:
            score_buckets['0-20'] += 1
        elif score <= 40:
            score_buckets['21-40'] += 1
        elif score <= 60:
            score_buckets['41-60'] += 1
        elif score <= 80:
            score_buckets['61-80'] += 1
        else:
            score_buckets['81-100'] += 1

    context = {
        "bucket_0_20": score_buckets["0-20"],
        "bucket_21_40": score_buckets["21-40"],
        "bucket_41_60": score_buckets["41-60"],
        "bucket_61_80": score_buckets["61-80"],
        "bucket_81_100": score_buckets["81-100"],
        'summary': summary,
        'recent_alerts': recent_alerts,
        'devices': device_list,
        'score_buckets': score_buckets,
        'top_tools': top_tools
    }

    return render(request, 'dashboard.html', context)

def parse_datetime_field(value):
    try:
        dt = parser.isoparse(value) if isinstance(value, str) else value
        if dt.tzinfo is None:
            dt = make_aware(dt)
        return dt
    except Exception:
        return None

@login_required
def device_list(request):
    """
    View for listing all devices
    """
    # Get all devices
    response = api_request('devices')
    if response:
        devices = response.get('devices', [])
        for device in devices:
            device["last_seen"] = parse_datetime_field(device.get("last_seen"))
            sec = api_request(f'devices/{device["id"]}/security')
            if sec and "security_data" in sec:
                device["is_compliant"] = sec["security_data"].get("compliant", device.get("is_compliant"))
    else:
        devices = []
        messages.error(request, "Could not retrieve device list from the API. Please try again later.")
    
    context = {
        'devices': devices
    }
    
    return render(request, 'devices/device_list.html', context)

@login_required
def device_detail(request, device_id):
    if request.method == 'POST':
        new_username = request.POST.get("username", "").strip()
        # Call a PATCH-like API to update the user field
        update_response = requests.post(
            f"{API_URL}/devices/{device_id}/update-username",
            json={"username": new_username}
        )
        if update_response.ok:
            messages.success(request, "User updated successfully.")
        else:
            messages.error(request, "Failed to update user.")
        return redirect("device_detail", device_id=device_id)
    """
    View for showing device details
    """
    # Get device details
    device_response = api_request(f'devices/{device_id}')
    if not device_response:
        messages.error(request, "Could not retrieve device details from the API. Please try again later.")
        return redirect('device_list')
    device_response["device"]["last_seen"] = parse_datetime_field(device_response["device"].get("last_seen"))

    # Get device security data
    security_response = api_request(f'devices/{device_id}/security')
    security_data = security_response.get("security_data", {}) if security_response else {}
    device_response["device"]["is_compliant"] = security_data.get("compliant", device_response["device"]["is_compliant"])

    # Get device software inventory
    software_response = api_request(f'devices/{device_id}/software')
    
    for sw in software_response.get("software", []):
        # Normalize booleans
        sw["is_vulnerable"] = bool(sw.get("is_vulnerable"))
        sw["is_outdated"] = bool(sw.get("is_outdated"))

    # Get device alerts
    alerts_response = api_request(f'devices/{device_id}/alerts')
    alerts = alerts_response.get('alerts', []) if alerts_response else []

    for alert in alerts:
        alert['first_seen'] = parse_datetime_field(alert.get('first_seen'))
        alert['last_seen'] = parse_datetime_field(alert.get('last_seen'))

        if alert['first_seen'] and alert['last_seen']:
            delta = alert['last_seen'] - alert['first_seen']
            minutes = int(delta.total_seconds() // 60)

            if alert.get('is_resolved'):
                alert['duration_display'] = "Resolved after " + format_duration(minutes)
            else:
                alert['duration_display'] = format_duration(minutes)
        else:
            alert['duration_display'] = "N/A"
    
    snapshots_response = api_request(f'devices/{device_id}/snapshots')
    snapshots = snapshots_response.get('snapshots', []) if snapshots_response else []

    chart_data = {
        'labels': [],
        'scores': [],
        'edr_flags': [],
        'dlp_flags': []
    }
    
    for snap in snapshots:
        dt_raw = snap['collected_at']
        try:
            dt_obj = datetime.fromisoformat(dt_raw)
            formatted_label = dt_obj.strftime('%b %d, %H:%M')
        except:
            formatted_label = dt_raw  # fallback if parse fails

        chart_data['labels'].append(formatted_label)
        score = min(round(snap['security_score'], 2), 100)
        chart_data['scores'].append(score)
        chart_data['edr_flags'].append(snap.get('edr_found', False))
        chart_data['dlp_flags'].append(snap.get('dlp_found', False))

    chart_data['edr_flags'] = json.dumps(chart_data['edr_flags'])
    chart_data['dlp_flags'] = json.dumps(chart_data['dlp_flags'])

    context = {
        'device': device_response.get('device', {}),
        'security_data': security_response.get('security_data', {}) if security_response else {},
        'software': software_response.get('software', []) if software_response else [],
        'alerts': alerts,
        'chart_data': chart_data
    }

    return render(request, 'devices/device_detail.html', context)

def format_duration(minutes):
    td = timedelta(minutes=minutes)
    days = td.days
    hours, remainder = divmod(td.seconds, 3600)
    mins = remainder // 60
    parts = []
    if days > 0:
        parts.append(f"{days}d")
    if hours > 0:
        parts.append(f"{hours}h")
    if mins > 0 or not parts:
        parts.append(f"{mins}m")
    return "Lasted for " + " ".join(parts)

@login_required
def alert_list(request):
    show_resolved = request.GET.get('show_resolved', 'false')

    # 🔁 Update severity before showing alerts
    api_request('alerts/refresh-severity', method='POST')

    response = api_request(f'alerts?show_resolved={show_resolved}')
    alerts = response.get('alerts', []) if response else []
    if not response:
        messages.error(request, "Could not retrieve alerts from the API. Please try again later.")

    # Parse and enrich alerts
    for alert in alerts:
        alert['first_seen'] = parse_datetime_field(alert.get('first_seen'))
        alert['last_seen'] = parse_datetime_field(alert.get('last_seen'))

        if alert['first_seen'] and alert['last_seen']:
            delta = alert['last_seen'] - alert['first_seen']
            minutes = int(delta.total_seconds() // 60)

            if alert.get('is_resolved'):
                alert['duration_display'] = "Resolved after " + format_duration(minutes)
            else:
                alert['duration_display'] = format_duration(minutes)
        else:
            alert['duration_display'] = "N/A"

    # ✅ Group alerts by hostname and device_id
    grouped_alerts = defaultdict(list)
    for alert in alerts:
        device_id = alert.get('device_id')
        hostname = alert.get('hostname', 'Unknown')
        group_key = f"{hostname} ({device_id[:6]})" 
        grouped_alerts[group_key].append(alert)

    context = {
        'grouped_alerts': grouped_alerts.items(),  # list of (hostname, [alerts])
        'show_resolved': show_resolved == 'true'
    }

    return render(request, 'alerts/alert_list.html', context)

@login_required
@require_POST
def resolve_alert(request, alert_id):
    """
    View for resolving an alert
    """
    # Call API to resolve alert
    response = api_request(f'alerts/{alert_id}/resolve', method='POST')
    
    if response and response.get('success'):
        messages.success(request, "Alert successfully resolved.")
    else:
        messages.error(request, "Failed to resolve alert. Please try again later.")
    
    # Redirect back to alerts page
    return redirect('alert_list')

def security_tools_overview(request):
    response = api_request('dashboard/security-tools-summary')

    print("🔍 API Response:", response)  # Add this line for debugging

    if not response:
        messages.error(request, "Unable to load security tools data.")
        return render(request, 'tools/tools.html', {
            'tools_summary': {},
            'missing_summary': {
                "total_devices": 0,
                "missing_edr": 0,
                "missing_dlp": 0,
                "missing_av": 0
            }
        })

    tools_summary = response.get("tools", {})
    missing_summary = response.get("missing_summary", {
        "total_devices": 0,
        "missing_edr": 0,
        "missing_dlp": 0,
        "missing_av": 0
    })

    return render(request, 'tools/tools.html', {
        'tools_summary': tools_summary,
        'missing_summary': missing_summary
    })

@login_required
def policy_list(request):
    """
    View for listing all policies
    """
    # Get all policies
    response = api_request('policies')
    if response:
        policies = response.get('policies', [])
    else:
        policies = []
        messages.error(request, "Could not retrieve policies from the API. Please try again later.")
    
    context = {
        'policies': policies
    }
    
    return render(request, 'policies/policy_list.html', context)

@login_required
def policy_create(request):
    """
    View for creating a new policy
    """
    if request.method == 'POST':
        # Get policy data from form
        policy_data = {
            'name': request.POST.get('name'),
            'description': request.POST.get('description'),
            'min_security_score': float(request.POST.get('min_security_score', 70.0)),
            'require_os_up_to_date': request.POST.get('require_os_up_to_date') == 'on',
            'require_antivirus': request.POST.get('require_antivirus') == 'on',
            'require_firewall': request.POST.get('require_firewall') == 'on',
            'require_edr': request.POST.get('require_edr') == 'on',
            'require_dlp': request.POST.get('require_dlp') == 'on',
            'max_missing_patches': int(request.POST.get('max_missing_patches', 0)),
            'software_penalty_per_vuln': float(request.POST.get('software_penalty_per_vuln', 5.0)),
            'max_software_penalty': float(request.POST.get('max_software_penalty', 20.0)),
        }
        
        # Call API to create policy
        response = api_request('policies', method='POST', data=policy_data)
        
        if response and response.get('success'):
            messages.success(request, "Policy successfully created.")
            return redirect('policy_list')
        else:
            messages.error(request, "Failed to create policy. Please try again later.")
    
    context = {}
    return render(request, 'policies/policy_create.html', context) 
    
@login_required
def policy_edit(request, policy_id):
    # Get policy from API
    response = api_request(f'policies')
    policies = response.get('policies', []) if response else []
    policy = next((p for p in policies if p['id'] == policy_id), None)

    if not policy:
        messages.error(request, "Policy not found.")
        return redirect('policy_list')

    if request.method == 'POST':
        update_data = {
            'name': request.POST.get('name'),
            'description': request.POST.get('description'),
            'min_security_score': float(request.POST.get('min_security_score', 70)),
            'require_os_up_to_date': request.POST.get('require_os_up_to_date') == 'on',
            'require_antivirus': request.POST.get('require_antivirus') == 'on',
            'require_firewall': request.POST.get('require_firewall') == 'on',
            'require_edr': request.POST.get('require_edr') == 'on',
            'require_dlp': request.POST.get('require_dlp') == 'on',
            'max_missing_patches': int(request.POST.get('max_missing_patches', 0)),
            'software_penalty_per_vuln': float(request.POST.get('software_penalty_per_vuln', 5)),
            'max_software_penalty': float(request.POST.get('max_software_penalty', 20)),
            'os_score_weight': float(request.POST.get('os_score_weight', 25)),
            'antivirus_score_weight': float(request.POST.get('antivirus_score_weight', 25)),
            'firewall_score_weight': float(request.POST.get('firewall_score_weight', 25)),
            'security_tools_score_weight': float(request.POST.get('security_tools_score_weight', 25)),
        }

        response = requests.patch(f"{API_URL}/policies/{policy_id}", json=update_data)

        if response.ok:
            messages.success(request, "Policy updated successfully.")
            return redirect('policy_list')
        else:
            messages.error(request, "Failed to update policy.")

    return render(request, 'policies/policy_edit.html', {'policy': policy})

@require_POST
@login_required
def policy_activate(request, policy_id):
    response = api_request(f'policies/{policy_id}/activate', method='POST')
    if response and response.get('success'):
        # 🔁 Trigger recheck after activation
        recheck_response = api_request('policies/recheck-compliance', method='POST')
        if recheck_response and recheck_response.get('success'):
            messages.success(request, f"Policy activated and rechecked {recheck_response['devices_checked']} devices.")
        else:
            messages.warning(request, "Policy activated, but recheck failed.")
    else:
        messages.error(request, "Failed to activate policy.")
    return redirect('policy_list')

@login_required
@require_POST
def policy_recheck(request):
    response = api_request('policies/recheck-compliance', method='POST')
    if response and response.get('success'):
        messages.success(request, f"Rechecked {response['devices_checked']} devices using policy '{response['policy_name']}'.")
    else:
        messages.error(request, "Failed to recheck devices against the policy.")
    return redirect('policy_list')

@login_required
@require_POST
def policy_delete(request, policy_id):
    response = api_request(f'policies/{policy_id}', method='DELETE')
    if response and response.get('success'):
        messages.success(request, "Policy deleted successfully.")
    else:
        messages.error(request, response.get('error', "Failed to delete policy."))
    return redirect('policy_list')

@login_required
def user_inventory(request):
    search = request.GET.get('search', '')
    response = api_request(f"user-inventory?search={search}")
    devices = response.get("devices", []) if response else []

    for device in devices:
        device["last_seen"] = parse_datetime_field(device.get("last_seen"))

    return render(request, "inventory/user_inventory.html", {
        "devices": devices,
        "search": search
    })

@login_required
def snapshot_trend_view(request):
    summary = api_request('snapshot-summary')  # call the Flask API
    if not summary:
        messages.error(request, "Could not load snapshot summary.")
        return redirect('dashboard')

    context = {
        'trends': summary.get('trends', []),
        'risk_bins': summary.get('risk_bins', {}),
        'worst_devices': summary.get('worst_devices', [])
    }
    return render(request, 'analytics/snapshot_trend.html', context)

@login_required
@require_POST
def resolve_alert(request, alert_id):
    # Step 1: Resolve the alert
    response = api_request(f'alerts/{alert_id}/resolve', method='POST')
    
    if response and response.get("success"):
        alert = response.get("alert", {})
        device_id = alert.get("device_id")

        # Step 2: Request a rescan for the device
        if device_id:
            rescan_response = api_request(f'devices/{device_id}/request-rescan', method='POST')
            if not rescan_response.get("success"):
                messages.warning(request, f"Alert resolved, but rescan request failed: {rescan_response.get('error', 'Unknown error')}")

        messages.success(request, "Alert resolved and rescan requested.")
    else:
        messages.error(request, f"Failed to resolve alert: {response.get('error', 'Unknown error')}")

    return redirect('alert_list')
