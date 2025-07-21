"""
Hygiene360 API
==============
Flask application for the Hygiene360 API.
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import json
import os
from datetime import datetime
import traceback

# Import models
from models.base import db, init_db
from models.device import Device
from models.security_data import SecurityData
from models.software import Software
from models.policy import Policy
from models.alert import Alert
from models.security_snapshot import SecuritySnapshot
from models.security_tool import SecurityTool
from models.score_breakdown import ScoreBreakdown
from models.policy import get_active_policy
from scoring import calculate_security_score
from sqlalchemy import func, case, cast, Date
from sqlalchemy import distinct
#from models.os_update import OSUpdate

import uuid

# Create Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Initialize the database
init_db()

# API Routes

@app.route('/api/device-data', methods=['POST'])
def receive_device_data():
    """
    Receive and process device security data
    """
    data = request.json
    print("🛠️ Incoming data:\n", json.dumps(data, indent=2))  # Add this line

    if not data:
        return jsonify({'error': 'Invalid data format'}), 400
    
    try:
        # 1) Extract & (if needed) create Device
        sysinfo   = data['system_info']
        device_id = sysinfo['device_id']
        device = db.session.get(Device, device_id)
        if not device:
            device = Device(
                id=device_id,
                hostname=sysinfo['hostname'],
                platform=sysinfo['platform'],
                platform_version=sysinfo.get('platform_version'),
                platform_release=sysinfo.get('platform_release'),
                architecture=sysinfo.get('architecture'),
                processor=sysinfo.get('processor')
            )
            db.add(device)
        
        sec = SecurityData(
            device_id=device_id,
            os_patch_status=data.get('os_patch_status'),
            antivirus_status=data.get('antivirus_status'),
            firewall_status=data.get('firewall_status'),
            security_tools_status=data.get('security_tools', {})
        )
        db.add(sec)
        
        # Update device security status
        device.update_security_status(
            antivirus_active=sec.antivirus_active,
            firewall_active=sec.firewall_active,
            os_up_to_date=sec.os_up_to_date,
            patches_missing=sec.patches_missing,
            security_score=sec.security_score
        )

        policy = get_active_policy()
        software_list = Software.query.filter_by(device_id=device_id).all()    
        score, breakdown = calculate_security_score(sec, software_list, policy)
        sec.security_score = score
        device.security_score = score
        compliance = policy.check_compliance(sec)
        device.is_compliant = compliance['compliant']

        snapshot_id = uuid.uuid4()
        snapshot = SecuritySnapshot(
            id=snapshot_id,
            device_id=device_id,
            collected_at=datetime.utcnow(),
            os_patch_status=data.get('os_patch_status'),
            antivirus_summary=data.get('antivirus_status'),
            firewall_summary=data.get('firewall_status'),
            edr_found=data.get('security_tools', {}).get('edr', {}).get('found', False),
            dlp_found=data.get('security_tools', {}).get('dlp', {}).get('found', False),
            security_score=score
        )
        db.add(snapshot)
        db.session.flush()

        for tool_type in ['antivirus', 'edr', 'dlp']:
                for tool in data.get('security_tools', {}).get(tool_type, {}).get('tools', []):
                    db.add(SecurityTool(
                        snapshot_id=snapshot_id,
                        device_id=device_id,
                        tool_type=tool_type,
                        tool_name=tool.get("name"),
                        found=tool.get("found", False),
                        installed=tool.get("status", "") in ["Installed", "Active"],
                        running=tool.get("details", {}).get("process", {}).get("running", False),
                        registry_found=tool.get("details", {}).get("registry", False),
                        start_mode=tool.get("details", {}).get("service", {}).get("start_mode", ""),
                        process_count=tool.get("details", {}).get("process", {}).get("count", 0),
                        raw_data=tool
                    ))
        
        Software.query.filter_by(device_id=device_id).delete()
        for sw in data.get('software_inventory',{}).get('common_software', []):
            db.add(Software(
                device_id=device_id,
                name=sw['name'],
                version=sw.get('version'),
                publisher=sw.get('publisher'),
                install_date=sw.get('install_date'),
                is_vulnerable=sw.get('vulnerable', False),
                outdated=sw.get('is_outdated', False),
                raw_data=sw,
                snapshot_id=snapshot_id
            ))

        # 6) Alerts
        new_or_updated_alerts = Alert.create_from_security_data(device_id, sec, policy)
        for alert in new_or_updated_alerts:
            db.session.merge(alert)
        
        for component in breakdown:
            db.add(ScoreBreakdown(
                snapshot_id=snapshot_id,
                component=component['component'],
                weight=component['weight'],
                achieved_score=component['achieved'],
                max_score=component['max']
            ))

        # 7) One single commit for the whole batch
        db.commit()

        return jsonify({
            'success': True,
            'device_id': device_id,
            'security_score': sec.security_score,
            'alerts_generated': len(Alert.create_from_security_data(device_id, sec, policy))
        }), 200

    except Exception as e:
        db.rollback()
        print("💥 Internal Server Error:", e)
        return jsonify({'error': str(e)}), 500

@app.route('/api/devices/<device_id>/snapshots', methods=['GET'])
def get_snapshots(device_id):
    try:
        snapshots = SecuritySnapshot.query.filter_by(device_id=device_id).order_by(SecuritySnapshot.collected_at.desc()).all()
        return jsonify({
            'device_id': device_id,
            'snapshots': [s.to_dict() for s in snapshots]
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    

@app.route('/api/devices', methods=['GET'])
def get_devices():

    """
    Get all devices
    """
    try:
        devices = Device.query.all()
        return jsonify({
            'devices': [device.to_dict() for device in devices]
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/devices/<device_id>', methods=['GET'])
def get_device(device_id):
    """
    Get a specific device
    """
    try:
        device = Device.query.get(device_id)
        if not device:
            return jsonify({'error': 'Device not found'}), 404
        
        return jsonify({
            'device': device.to_dict()
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/devices/<device_id>/security', methods=['GET'])
def get_device_security(device_id):
    """
    Get security data for a specific device
    """
    try:
        device = Device.query.get(device_id)
        if not device:
            return jsonify({'error': 'Device not found'}), 404

        # Get the latest security data
        security_data = SecurityData.query.filter_by(device_id=device_id).order_by(
            SecurityData.collected_at.desc()
        ).first()

        if not security_data:
            return jsonify({'error': 'No security data available for this device'}), 404

        # Get policy and compliance check
        policy = get_active_policy()
        compliance = policy.check_compliance(security_data)

        # Fetch breakdown linked to latest snapshot
        latest_snapshot = SecuritySnapshot.query.filter_by(device_id=device_id).order_by(SecuritySnapshot.collected_at.desc()).first()
        score_breakdown = []
        if latest_snapshot:
            score_breakdown = ScoreBreakdown.query.filter_by(snapshot_id=latest_snapshot.id).all()
            score_breakdown = [ {
                'component': s.component,
                'weight': s.weight,
                'achieved': s.achieved_score,
                'max': s.max_score
            } for s in score_breakdown ]

        # Return extended data
        return jsonify({
            'device': device.to_dict(),
            'security_data': {
                **security_data.to_dict(),
                'score_breakdown': score_breakdown,
                'details': compliance['details'],
                'compliant': compliance['compliant']
            }
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/devices/<device_id>/software', methods=['GET'])
def get_device_software(device_id):
    """
    Get software inventory for a specific device
    """
    try:
        device = Device.query.get(device_id)
        if not device:
            return jsonify({'error': 'Device not found'}), 404
        
        software = Software.query.filter_by(device_id=device_id).all()
        
        return jsonify({
            'device_id': device_id,
            'software': [sw.to_dict() for sw in software]
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/devices/<device_id>/alerts', methods=['GET'])
def get_device_alerts(device_id):
    """
    Get alerts for a specific device
    """
    try:
        device = Device.query.get(device_id)
        if not device:
            return jsonify({'error': 'Device not found'}), 404
        
        # Get active (unresolved) alerts by default
        show_resolved = request.args.get('show_resolved', 'false').lower() == 'true'
        
        if show_resolved:
            alerts = Alert.query.filter_by(device_id=device_id).order_by(
                Alert.severity.desc(), Alert.created_at.desc()
            ).all()
        else:
            alerts = Alert.query.filter_by(device_id=device_id, is_resolved=False).order_by(
                Alert.severity.desc(), Alert.created_at.desc()
            ).all()
        
        return jsonify({
            'device_id': device_id,
            'alerts': [alert.to_dict() for alert in alerts]
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/alerts', methods=['GET'])
def get_all_alerts():
    """
    Get all alerts with device hostnames included.
    """
    try:
        # Get active (unresolved) alerts by default
        show_resolved = request.args.get('show_resolved', 'false').lower() == 'true'

        # Fetch alerts based on resolution status
        if show_resolved:
            alerts = Alert.query.order_by(
                Alert.severity.desc(), Alert.created_at.desc()
            ).all()
        else:
            alerts = Alert.query.filter_by(is_resolved=False).order_by(
                Alert.severity.desc(), Alert.created_at.desc()
            ).all()

        # Optimize device lookup: fetch all devices at once
        device_ids = {alert.device_id for alert in alerts}
        devices = Device.query.filter(Device.id.in_(device_ids)).all()
        device_map = {device.id: device.hostname for device in devices}

        # Include hostname in each alert
        enriched_alerts = []
        for alert in alerts:
            alert_dict = alert.to_dict()
            alert_dict['hostname'] = device_map.get(alert.device_id, "Unknown")
            enriched_alerts.append(alert_dict)

        return jsonify({'alerts': enriched_alerts}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/alerts/<alert_id>/resolve', methods=['POST'])
def resolve_alert(alert_id):
    """
    Resolve an alert
    """
    try:
        alert = Alert.query.get(alert_id)
        if not alert:
            return jsonify({'error': 'Alert not found'}), 404
        
        alert.resolve()
        db.commit()
        
        return jsonify({
            'success': True,
            'alert': alert.to_dict()
        }), 200
    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/policies', methods=['GET'])
def get_policies():
    """
    Get all policies
    """
    try:
        policies = Policy.query.all()
        return jsonify({
            'policies': [policy.to_dict() for policy in policies]
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/policies', methods=['POST'])
def create_policy():
    """
    Create a new policy
    """
    try:
        data = request.json
        if not data or 'name' not in data:
            return jsonify({'error': 'Invalid policy data'}), 400
        
        Policy.query.update({Policy.is_active: False})

        policy = Policy(
            name=data.get('name'),
            description=data.get('description'),
            min_security_score=data.get('min_security_score', 70.0),
            require_os_up_to_date=data.get('require_os_up_to_date', True),
            require_antivirus=data.get('require_antivirus', True),
            require_firewall=data.get('require_firewall', True),
            require_edr=data.get('require_edr', False),
            require_dlp=data.get('require_dlp', False),
            max_missing_patches=data.get('max_missing_patches', 0),
            custom_rules=data.get('custom_rules')
        )
        policy.is_active = True

        db.add(policy)
        db.commit()
        
        return jsonify({
            'success': True,
            'policy': policy.to_dict()
        }), 201
    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/dashboard/summary', methods=['GET'])
def get_dashboard_summary():
    """
    Get summary data for the dashboard
    """
    try:
        # Get device counts
        total_devices = Device.query.count()
        compliant_devices = Device.query.filter_by(is_compliant=True).count()
        
        # Get alert counts
        critical_alerts = Alert.query.filter_by(severity=3, is_resolved=False).count()
        high_alerts = Alert.query.filter_by(severity=2, is_resolved=False).count()
        medium_alerts = Alert.query.filter_by(severity=1, is_resolved=False).count()
        low_alerts = Alert.query.filter_by(severity=0, is_resolved=False).count()
        
        # Get average security score
        devices = Device.query.all()
        avg_score = sum(device.security_score for device in devices) / total_devices if total_devices > 0 else 0
        
        # Get security feature adoption rates
        antivirus_rate = Device.query.filter_by(antivirus_active=True).count() / total_devices if total_devices > 0 else 0
        firewall_rate = Device.query.filter_by(firewall_active=True).count() / total_devices if total_devices > 0 else 0
        
        edr_enabled = SecurityData.query.filter_by(edr_active=True).count()
        dlp_enabled = SecurityData.query.filter_by(dlp_active=True).count()

        return jsonify({
            'device_stats': {
                'total': total_devices,
                'compliant': compliant_devices,
                'compliance_rate': compliant_devices / total_devices if total_devices > 0 else 0
            },
            'alert_stats': {
                'critical': critical_alerts,
                'high': high_alerts,
                'medium': medium_alerts,
                'low': low_alerts,
                'total': critical_alerts + high_alerts + medium_alerts + low_alerts
            },
            'security_score': {
                'average': avg_score
            },
            'security_features': {
                'antivirus_rate': antivirus_rate,
                'firewall_rate': firewall_rate,
                'edr_rate': edr_enabled / total_devices if total_devices > 0 else 0,
                'dlp_rate': dlp_enabled / total_devices if total_devices > 0 else 0,
            }
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/devices/<device_id>/update-username', methods=['POST'])
def update_device_user(device_id):
    data = request.get_json()
    new_username = data.get("username", "").strip()
    device = Device.query.get(device_id)
    
    if not device:
        return jsonify({"error": "Device not found"}), 404
    
    device.username = new_username
    db.session.commit()
    return jsonify({"success": True, "user": new_username}), 200

@app.route('/api/dashboard/security-tools-summary', methods=['GET'])
def get_security_tools_summary():
    summary = {"edr": [], "dlp": [], "antivirus": []}
    total_devices = Device.query.count()

    # Tool breakdown
    for tool_type in summary.keys():
        results = db.session.query(
            SecurityTool.tool_type,
            SecurityTool.tool_name,
            func.count(func.distinct(SecurityTool.device_id)).label("installed"),
            func.count(func.distinct(
                case(
                    (SecurityTool.running == True, SecurityTool.device_id)
                )
            )).label("running")
        ).filter(
            SecurityTool.found == True,
            SecurityTool.tool_type == tool_type
        ).group_by(SecurityTool.tool_type, SecurityTool.tool_name).all()

        summary[tool_type] = [
            {"name": tool_name, "installed": installed, "running": running}
            for _tool_type, tool_name, installed, running in results
        ]

    # Devices without security layers
    edr_devices = db.session.query(distinct(SecurityTool.device_id)).filter_by(tool_type='edr', found=True).all()
    dlp_devices = db.session.query(distinct(SecurityTool.device_id)).filter_by(tool_type='dlp', found=True).all()
    av_devices = db.session.query(distinct(SecurityTool.device_id)).filter_by(tool_type='antivirus', found=True).all()

    edr_ids = set([row[0] for row in edr_devices])
    dlp_ids = set([row[0] for row in dlp_devices])
    av_ids = set([row[0] for row in av_devices])

    all_ids = set([d.id for d in Device.query.all()])

    missing_summary = {
        "total_devices": total_devices,
        "missing_edr": len(all_ids - edr_ids),
        "missing_dlp": len(all_ids - dlp_ids),
        "missing_av": len(all_ids - av_ids)
    }

    return jsonify({
        "tools": summary,
        "missing_summary": missing_summary
    }), 200

@app.route('/api/policies/<int:policy_id>', methods=['PATCH'])
def update_policy(policy_id):
    policy = Policy.query.get(policy_id)
    if not policy:
        return jsonify({'error': 'Policy not found'}), 404

    data = request.json
    for field in [
        'name', 'description', 'min_security_score', 'require_os_up_to_date',
        'require_antivirus', 'require_firewall', 'require_edr', 'require_dlp',
        'max_missing_patches', 'software_penalty_per_vuln', 'max_software_penalty'
    ]:
        if field in data:
            setattr(policy, field, data[field])

    db.session.commit()
    return jsonify({'success': True, 'policy': policy.to_dict()})

@app.route('/api/policies/<int:policy_id>/activate', methods=['POST'])
def activate_policy(policy_id):
    try:
        # Deactivate all policies
        Policy.query.update({Policy.is_active: False})
        
        # Activate the selected one
        policy = Policy.query.get(policy_id)
        if not policy:
            return jsonify({'error': 'Policy not found'}), 404
        
        policy.is_active = True
        db.session.commit()
        
        refreshed = Policy.query.get(policy_id)

        return jsonify({'success': True, 'policy': refreshed.to_dict()}), 200
    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/policies/recheck-compliance', methods=['POST'])
def recheck_all_device_compliance():
    try:
        policy = get_active_policy()
        if not policy:
            return jsonify({'error': 'No active policy found'}), 400

        # 🧹 Clear unresolved alerts related to policy
        db.session.query(Alert).filter(
            Alert.is_resolved == False,
            Alert.category.in_(['score', 'patch', 'antivirus', 'firewall', 'edr', 'dlp'])
        ).delete(synchronize_session=False)

        devices = Device.query.all()
        updated = 0

        for device in devices:
            # Get latest security data
            sec = SecurityData.query.filter_by(device_id=device.id).order_by(
                SecurityData.collected_at.desc()
            ).first()
            if not sec:
                continue

            software_list = Software.query.filter_by(device_id=device.id).all()
            score, breakdown = calculate_security_score(sec, software_list, policy)
            sec.security_score = score
            device.security_score = score

            # ✅ Update compliance
            compliance = policy.check_compliance(sec)
            device.is_compliant = compliance['compliant']

            # ✅ Generate fresh alerts
            new_alerts = Alert.create_from_security_data(device.id, sec, policy)
            for alert in new_alerts:
                db.session.add(alert)

            updated += 1

        db.session.commit()

        return jsonify({
            'success': True,
            'devices_checked': updated,
            'policy_id': policy.id,
            'policy_name': policy.name
        }), 200

    except Exception as e:
        traceback.print_exc()
        db.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/policies/<int:policy_id>', methods=['DELETE'])
def delete_policy(policy_id):
    try:
        policy = Policy.query.get(policy_id)
        if not policy:
            return jsonify({'error': 'Policy not found'}), 404
        
        if policy.is_active:
            return jsonify({'error': 'Cannot delete an active policy'}), 400
        
        db.session.delete(policy)
        db.commit()
        return jsonify({'success': True}), 200
    except Exception as e:
        traceback.print_exc()
        db.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/user-inventory', methods=['GET'])
def get_user_inventory():
    """
    Return a list of all devices with optional search by hostname or username.
    """
    search = request.args.get('search', '').strip().lower()

    query = Device.query

    if search:
        query = query.filter(
            func.lower(Device.hostname).like(f"%{search}%") |
            func.lower(Device.username).like(f"%{search}%")
        )

    devices = query.order_by(Device.username.asc(), Device.hostname.asc()).all()

    return jsonify({
        "devices": [device.to_dict() for device in devices]
    }), 200

@app.route('/api/snapshot-summary', methods=['GET'])
def snapshot_summary():
    try:
        # Group by day
        scores_by_day = (
            db.session.query(
                cast(SecuritySnapshot.collected_at, Date).label("date"),
                func.avg(SecuritySnapshot.security_score).label("avg_score"),
                func.count(SecuritySnapshot.id).label("count")
            )
            .group_by("date")
            .order_by("date")
            .all()
        )

        # Risk category breakdown
        risk_bins = {
            "high": db.session.query(func.count()).filter(SecuritySnapshot.security_score >= 80).scalar(),
            "medium": db.session.query(func.count()).filter(SecuritySnapshot.security_score >= 60, SecuritySnapshot.security_score < 80).scalar(),
            "low": db.session.query(func.count()).filter(SecuritySnapshot.security_score < 60).scalar()
        }

        # Top 5 devices with lowest recent score
        worst_devices = (
            db.session.query(
                Device.id,
                Device.hostname,
                func.min(SecuritySnapshot.security_score)
            )
            .join(Device, Device.id == SecuritySnapshot.device_id)
            .group_by(Device.id, Device.hostname)
            .order_by(func.min(SecuritySnapshot.security_score))
            .limit(5)
            .all()
        )

        return jsonify({
            "trends": [{"date": str(d.date), "avg_score": float(d.avg_score), "count": d.count} for d in scores_by_day],
            "risk_bins": risk_bins,
            "worst_devices": [
                {
                    "device_id": d[0],
                    "hostname": d[1],
                    "min_score": round(float(d[2]), 2)
                } for d in worst_devices
            ]
        }), 200

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@app.route('/api/devices/<device_id>/request-rescan', methods=['POST'])
def request_device_rescan(device_id):
    device = Device.query.get(device_id)
    if not device:
        return jsonify({"error": "Device not found"}), 404

    device.rescan_requested = True
    db.session.commit()
    return jsonify({"success": True}), 200

@app.route('/api/devices/<device_id>/rescan-request', methods=['GET'])
def check_rescan_request(device_id):
    device = Device.query.get(device_id)
    if not device:
        return jsonify({"error": "Device not found"}), 404

    return jsonify({"rescan_requested": device.rescan_requested}), 200

@app.route('/api/devices/<device_id>/update-rescan-status', methods=['POST'])
def update_rescan_status(device_id):
    device = Device.query.get(device_id)
    if not device:
        return jsonify({"error": "Device not found"}), 404

    data = request.get_json()
    device.rescan_requested = data.get("rescan_requested", False)
    db.session.commit()
    return jsonify({"success": True}), 200

@app.route('/api/alerts/refresh-severity', methods=['POST'])
def refresh_alert_severity():
    try:
        now = datetime.utcnow()
        active_alerts = Alert.query.filter_by(is_resolved=False).all()

        for alert in active_alerts:
            age = now - alert.first_seen
            new_severity = Alert.compute_severity_from_age(age)
            alert.last_seen = now
            alert.severity = new_severity

        db.session.commit()

        return jsonify({'success': True, 'alerts_updated': len(active_alerts)})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/')
def index():
    """
    API root endpoint
    """
    return jsonify({
        'name': 'Hygiene360 API',
        'version': '1.0.0',
        'status': 'running'
    })

@app.teardown_appcontext
def shutdown_session(exception=None):
    db.session.remove()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False) 