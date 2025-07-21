def calculate_security_score(security_data, software_list, policy):
    breakdown = []

    # OS score
    os_score = 0.0
    os_max = policy.os_score_weight if getattr(policy, "require_os_up_to_date", True) else 0
    if os_max > 0:
        if security_data.os_up_to_date:
            os_score += 0.5
        if security_data.patches_missing <= policy.max_missing_patches:
            os_score += 0.5
        os_score_final = os_score * policy.os_score_weight
        breakdown.append({
            'component': 'OS',
            'weight': policy.os_score_weight,
            'achieved': os_score_final,
            'max': policy.os_score_weight
        })
    else:
        os_score_final = 0.0

    # Antivirus score
    av_score_final = 0.0
    if getattr(policy, "require_antivirus", True):
        av_score = 1.0 if security_data.antivirus_active else 0.0
        av_score_final = av_score * policy.antivirus_score_weight
        breakdown.append({
            'component': 'Antivirus',
            'weight': policy.antivirus_score_weight,
            'achieved': av_score_final,
            'max': policy.antivirus_score_weight
        })

    # Firewall score
    fw_score_final = 0.0
    if getattr(policy, "require_firewall", True):
        fw_score = 1.0 if security_data.firewall_active else 0.0
        fw_score_final = fw_score * policy.firewall_score_weight
        breakdown.append({
            'component': 'Firewall',
            'weight': policy.firewall_score_weight,
            'achieved': fw_score_final,
            'max': policy.firewall_score_weight
        })

    # Security Tools score (EDR/DLP)
    tools_score_final = 0.0
    security_tools_weight = policy.security_tools_score_weight
    edr_tools = security_data.security_tools_status.get("edr", {}).get("tools", [])
    dlp_tools = security_data.security_tools_status.get("dlp", {}).get("tools", [])

    def get_tool_score(tool_list):
        for tool in tool_list:
            installed = tool.get("status", "").lower() in ["installed", "active"]
            running = tool.get("details", {}).get("process", {}).get("running", False)
            if installed and running:
                return 1.0
            elif installed:
                return 0.5
        return 0.0

    edr_score = get_tool_score(edr_tools) if getattr(policy, "require_edr", False) else None
    dlp_score = get_tool_score(dlp_tools) if getattr(policy, "require_dlp", False) else None

    tool_scores = [s for s in [edr_score, dlp_score] if s is not None]

    if tool_scores:
        tools_score_ratio = sum(tool_scores) / len(tool_scores)
        tools_score_final = tools_score_ratio * security_tools_weight
        breakdown.append({
            'component': 'Security Tools',
            'weight': security_tools_weight,
            'achieved': tools_score_final,
            'max': security_tools_weight
        })

    # Software penalty
    vulnerable_penalty = 0
    for sw in software_list:
        if sw.is_vulnerable:
            vulnerable_penalty += getattr(policy, "software_penalty_per_vuln", 5)

    vulnerable_penalty = min(vulnerable_penalty, getattr(policy, "max_software_penalty", 20))
    if vulnerable_penalty > 0:
        breakdown.append({
            'component': 'Vulnerable Software',
            'weight': -getattr(policy, "max_software_penalty", 20),
            'achieved': -vulnerable_penalty,
            'max': 0
        })

    # Final score
    achieved_total = 0.0
    max_total = 0.0

    for entry in breakdown:
        achieved_total += entry['achieved']
        max_total += entry['weight'] if entry['weight'] > 0 else 0  # skip penalty in max

    # Normalize to 0–100
    if max_total > 0:
        normalized_score = (achieved_total / max_total) * 100
    else:
        normalized_score = 0.0

    normalized_score = max(0.0, min(100.0, normalized_score))  # Clamp to 0–100

    return normalized_score, breakdown
