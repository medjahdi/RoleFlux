import os
from google import genai
from src.models.finding import Finding

def generate_triage_context(finding: Finding):
    try:
        project_id = os.environ.get("TF_VAR_project_id", "roleflux-prod-1234")
        # Initialize the Vertex AI Gemini client
        client = genai.Client(vertexai=True, project=project_id, location="us-central1")
        
        prompt = f"""
You are a Senior Cloud Security Responder for GCP.
An anomaly has been detected in the environment.
Analyze the following finding payload:
{finding.model_dump_json(indent=2)}

You must output your response in EXACTLY this format, with no extra conversational text:

SUMMARY:
[Write a sharp, 2-sentence explanation of what the attacker did and why it's critical]

REMEDIATION:
[Write a SINGLE, exact gcloud CLI command that the engineer can copy-paste to revert or block the action. Do not include markdown codeblocks around it, just the raw command.]
"""
        
        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=prompt,
        )
        
        text = response.text
        
        summary = ""
        remediation = ""
        
        if "SUMMARY:" in text and "REMEDIATION:" in text:
            parts = text.split("REMEDIATION:")
            summary = parts[0].replace("SUMMARY:", "").strip()
            remediation = parts[1].strip().replace("`", "")
        else:
            summary = text.strip()[:200] + "..."
            remediation = "gcloud auth login # Review manually"
            
        finding.ai_summary = summary
        finding.ai_remediation = remediation
        print(f"[AI Triage] Successfully generated context for {finding.id}")
        
    except Exception as e:
        print(f"[AI Triage] Failed to generate AI context: {e}")
