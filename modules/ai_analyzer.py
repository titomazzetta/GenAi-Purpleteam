"""
AI Analyzer module.
Handles communication with LLM (Ollama or OpenAI) and generates insights.
"""
import json
import requests
import os

def call_llm(config, prompt, json_mode=False):
    provider = config['ai']['provider']
    if provider == "openai":
        import openai
        openai.api_key = config['ai']['api_key']
        response = openai.ChatCompletion.create(
            model=config['ai']['model'],
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3,
            response_format={"type": "json_object"} if json_mode else None
        )
        return response.choices[0].message.content
    elif provider == "ollama":
        url = f"{config['ai']['base_url']}/api/generate"
        payload = {
            "model": config['ai']['model'],
            "prompt": prompt,
            "stream": False,
            "format": "json" if json_mode else ""
        }
        response = requests.post(url, json=payload)
        response.raise_for_status()
        return response.json()['response']
    else:
        raise ValueError(f"Unknown AI provider: {provider}")

def analyze(config, run_id, verbose=False):
    if verbose: print("[VERBOSE] Running AI analysis on enriched bundle...")
    run_dir = f"{config['paths']['runs_base']}/{run_id}"
    bundle_file = f"{run_dir}/processed/enriched_bundle.json"
    if not os.path.exists(bundle_file):
        print("[!] Enriched bundle not found. Run collection first.")
        return

    with open(bundle_file) as f:
        bundle = json.load(f)

    prompt = f"""You are a senior SOC analyst. Analyze the following incident timeline and logs from a simulated phishing attack in a healthcare environment. Provide:

1. Executive summary (2-3 sentences).
2. Technical timeline of key events (include timestamps and descriptions).
3. IOCs (IPs, domains, file paths) with confidence (high/medium/low).
4. MITRE ATT&CK techniques observed and explanation.
5. Recommended hardening measures (specific to healthcare data).
6. Awareness training points for employees.
7. Draft Sigma rule(s) to detect similar activity.
8. Draft Suricata rule(s) for network detection.

Incident bundle: {json.dumps(bundle, indent=2)}

Format your response as JSON with keys: executive_summary, technical_timeline (list of dicts with time, event), iocs (list of dicts with type, value, confidence), mitre_techniques (list of dicts with id, name, explanation), hardening_measures (list), awareness_points (list), sigma_rules (list of strings), suricata_rules (list of strings).
"""

    if verbose: print("[VERBOSE] Sending prompt to LLM...")
    try:
        ai_response = call_llm(config, prompt, json_mode=True)
        insights = json.loads(ai_response)
        if verbose: print("[VERBOSE] AI analysis received and parsed.")
    except Exception as e:
        print(f"[!] AI analysis failed: {e}")
        insights = {"error": str(e), "raw_response": ai_response if 'ai_response' in locals() else ""}

    with open(f"{run_dir}/processed/ai_insights.json", "w") as f:
        json.dump(insights, f, indent=2)

    iocs = insights.get('iocs', [])
    stix_bundle = generate_stix(iocs)
    os.makedirs(f"{run_dir}/iocs", exist_ok=True)
    with open(f"{run_dir}/iocs/iocs.stix.json", "w") as f:
        json.dump(stix_bundle, f, indent=2)

    os.makedirs(f"{run_dir}/rules", exist_ok=True)
    if 'sigma_rules' in insights:
        for i, rule in enumerate(insights['sigma_rules']):
            with open(f"{run_dir}/rules/sigma_{i+1}.yml", "w") as f:
                f.write(rule)
    if 'suricata_rules' in insights:
        with open(f"{run_dir}/rules/suricata_custom.rules", "w") as f:
            for rule in insights['suricata_rules']:
                f.write(rule + "\n")

    if verbose: print("[VERBOSE] Insights, STIX IOCs, and rules saved.")
    print(f"[+] AI analysis complete. Insights saved to {run_dir}/processed/ai_insights.json")

def generate_stix(iocs):
    objects = []
    for ioc in iocs:
        ioc_type = ioc.get('type')
        value = ioc.get('value')
        if ioc_type == 'ipv4-addr':
            obj = {
                "type": "ipv4-addr",
                "spec_version": "2.1",
                "id": f"ipv4-addr--{abs(hash(value)) % 10**10}",
                "value": value
            }
        elif ioc_type == 'domain-name':
            obj = {
                "type": "domain-name",
                "spec_version": "2.1",
                "id": f"domain-name--{abs(hash(value)) % 10**10}",
                "value": value
            }
        else:
            continue
        objects.append(obj)
    return {
        "type": "bundle",
        "id": f"bundle--{abs(hash(str(iocs))) % 10**10}",
        "spec_version": "2.1",
        "objects": objects
    }
