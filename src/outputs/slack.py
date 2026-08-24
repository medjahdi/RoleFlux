import os
import json
import requests

def send_slack_alert(finding_json: str):
    webhook_url = os.environ.get("SLACK_WEBHOOK_URL")
    if not webhook_url or webhook_url == "https://example.com":
        print(f"[Slack Output Module] Webhook not configured. Would have sent: {finding_json}")
        return

    try:
        finding = json.loads(finding_json)
        
        severity = finding.get("severity", "INFO")
        
        emoji_map = {
            "CRITICAL": "🚨",
            "HIGH": "🔥",
            "MEDIUM": "⚠️",
            "LOW": "👀",
            "INFO": "ℹ️"
        }
        severity_emoji = emoji_map.get(severity, "ℹ️")

        blocks = {
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": f"{severity_emoji} Triage Report: {severity} Alert"
                    }
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": f"*Security Level:*\n`{severity}`"
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Risk Score:*\n{finding.get('risk_score')}/100"
                        }
                    ]
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Actors & Targets:*\nActors: {', '.join(finding.get('actors', []))}\nTargets: {', '.join(finding.get('targets', []))}"
                    }
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Event Description:*\n```{finding.get('description')}```"
                    }
                }
            ]
        }
        
        if finding.get("ai_summary") and finding.get("ai_remediation"):
            blocks["blocks"].extend([
                {
                    "type": "divider"
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"✨ *Vertex AI Executive Summary:*\n{finding.get('ai_summary')}"
                    }
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"🛠️ *Instant Remediation Command:*\n```{finding.get('ai_remediation')}```"
                    }
                }
            ])
        
        response = requests.post(webhook_url, json=blocks)
        response.raise_for_status()
        print("[Slack Output Module] Successfully sent alert to Slack!")
    except Exception as e:
        print(f"[Slack Output Module] Failed to send alert: {e}")
