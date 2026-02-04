import logging
import sys
import json
import datetime
import os
from typing import Dict, Any

from fastmcp import FastMCP
from llm_guard.input_scanners import PromptInjection
from llm_guard.output_scanners.sensitive import Sensitive

# --- Absolute Path Setup ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(SCRIPT_DIR, "config.json")
LOG_FILE = os.path.join(SCRIPT_DIR, "security_events.json")
GENERATED_REGEX_FILE = os.path.join(SCRIPT_DIR, "generated_regex.json")

# --- Basic Setup ---
logging.basicConfig(stream=sys.stderr, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
app = FastMCP()

# --- Configuration and State ---
IS_TAINTED: bool = False

def load_config():
    """Loads the configuration from config.json using an absolute path."""
    try:
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        # This is a critical error, but we provide safe defaults to avoid crashing.
        logging.error(f"FATAL: Could not load or parse config.json from {CONFIG_FILE}")
        return {
            "enable_prompt_injection_scanner": False,
            "prompt_injection_threshold": 1.0,
            "pii_scan_redact": False,
            "pii_entities_to_scan": [],
            "custom_regex_patterns": []
        }

def get_scanners(config: Dict[str, Any]):
    """Initializes scanners based on the provided configuration."""
    custom_patterns = config.get("custom_regex_patterns", [])
    with open(GENERATED_REGEX_FILE, "w") as f:
        json.dump(custom_patterns, f, indent=4)
    
    prompt_scanner = PromptInjection(threshold=config.get("prompt_injection_threshold", 0.99))
    pii_scanner = Sensitive(
        entity_types=config.get("pii_entities_to_scan", []),
        redact=config.get("pii_scan_redact", True),
        threshold=config.get("pii_scan_threshold", 0.1),
        regex_pattern_groups_path=GENERATED_REGEX_FILE
    )
    return prompt_scanner, pii_scanner

# --- Logging System ---
def log_event(event_type: str, details: Any, score: float, action: str):
    """Appends a structured security event to the JSON log file."""
    event = {
        "timestamp": datetime.datetime.utcnow().isoformat(), "event_type": event_type,
        "details": details, "risk_score": score, "action": action
    }
    try:
        data = []
        if os.path.exists(LOG_FILE) and os.path.getsize(LOG_FILE) > 0:
            with open(LOG_FILE, "r") as f:
                data = json.load(f)
        data.append(event)
        with open(LOG_FILE, "w") as f:
            json.dump(data, f, indent=4)
    except Exception as e:
        logging.error(f"FATAL: Could not write to log file {LOG_FILE}: {e}")

# --- Aegis Security Tools (Generic Middleware) ---
@app.tool()
def analyze_incoming_content(content_to_scan: str) -> Dict[str, Any]:
    """Scans inbound text for prompt injection."""
    global IS_TAINTED
    config = load_config() # Reload config on every call
    prompt_injection_scanner, _ = get_scanners(config)
    risk_score = 0.0

    if config.get("enable_prompt_injection_scanner", True):
        _, is_valid, risk_score = prompt_injection_scanner.scan(content_to_scan)
        if not is_valid:
            IS_TAINTED = True
            details = {"reason": "High-risk prompt injection attempt detected.", "original_content": content_to_scan}
            log_event("INJECTION_DETECTED", details, risk_score, "BLOCKED_INPUT")
            return {"status": "SECURITY_ALERT", "action": "BLOCKED_INPUT", "is_valid": False, "risk_score": risk_score}
    
    log_event("INFO", {"content": content_to_scan}, risk_score, "ALLOWED_INPUT")
    return {"status": "SUCCESS", "action": "ALLOWED_INPUT", "is_valid": True, "risk_score": risk_score}

@app.tool()
def scan_output_data(data_to_scan: str) -> Dict[str, Any]:
    """Scans outbound text for sensitive PII."""
    global IS_TAINTED
    config = load_config() # Reload config on every call
    _, pii_scanner = get_scanners(config)

    if IS_TAINTED:
        details = {"reason": "Access denied because session is tainted."}
        log_event("ACCESS_DENIED", details, 1.0, "DENIED_ACCESS")
        return {"status": "ACCESS_DENIED", "action": "DENIED_ACCESS", "risk_score": 1.0}

    sanitized_output, is_valid, risk_score = pii_scanner.scan(prompt="scan", output=data_to_scan)
    if not is_valid:
        details = {"original_data": data_to_scan, "redacted_data": sanitized_output, "reason": "Sensitive PII detected and redacted."}
        log_event("PII_REDACTED", details, risk_score, "REDACTED_OUTPUT")
        return {"status": "SUCCESS_REDACTED", "action": "REDACTED_OUTPUT", "risk_score": risk_score, "sanitized_data": sanitized_output}

    log_event("INFO", {"data": data_to_scan}, 0.0, "ALLOWED_OUTPUT")
    return {"status": "SUCCESS", "action": "ALLOWED_OUTPUT", "risk_score": 0.0, "sanitized_data": data_to_scan}

@app.tool()
def reset_security_session() -> Dict[str, str]:
    """Resets the session's security state."""
    global IS_TAINTED
    IS_TAINTED = False
    log_event("ADMIN_ACTION", {"action": "Session reset"}, 0.0, "SESSION_RESET")
    return {"status": "SUCCESS", "message": "Security session has been reset."}

if __name__ == "__main__":
    app.run()
