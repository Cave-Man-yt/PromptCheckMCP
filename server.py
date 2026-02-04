import logging
import sys
import json
import datetime
import os
from typing import Dict, Any

from fastmcp import FastMCP
from llm_guard.input_scanners import PromptInjection
from llm_guard.input_scanners.anonymize import default_entity_types
from llm_guard.output_scanners.sensitive import Sensitive

# --- Absolute Path Setup ---
# Get the absolute path of the directory containing the current script
# This ensures that file paths work correctly even when the script is
# run from a different working directory.
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(SCRIPT_DIR, "config.json")
LOG_FILE = os.path.join(SCRIPT_DIR, "security_events.json")
GENERATED_REGEX_FILE = os.path.join(SCRIPT_DIR, "generated_regex.json")


# --- Basic Setup ---
# Configure logging to stderr to avoid interfering with MCP's JSON-RPC stdout.
logging.basicConfig(stream=sys.stderr, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Initialize the FastMCP application. This object will hold our tools.
app = FastMCP()

# --- Configuration and Security State ---
def load_config():
    """Loads the configuration from config.json using an absolute path."""
    try:
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logging.error(f"FATAL: Could not load or parse config.json: {e}")
        return {} # Return empty config on error

CONFIG = load_config()

# Global flag to track if the session has been compromised by malicious input.
IS_TAINTED: bool = False

# Ensure the log file exists and is a valid JSON list.
if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, "w") as f:
        json.dump([], f)

# --- Logging System ---
def log_event(event_type: str, details: Any, score: float, action: str):
    """Appends a structured security event to the JSON log file using an absolute path."""
    logging.info(f"Logging event: {event_type}, Action: {action}")
    event = {
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "event_type": event_type,
        "details": details,
        "risk_score": score,
        "action": action,
    }
    try:
        # Use r+ to read and write, ensuring file is not truncated on open
        with open(LOG_FILE, "r+") as f:
            data = json.load(f)
            data.append(event)
            f.seek(0)
            json.dump(data, f, indent=4)
            f.truncate()
    except (IOError, json.JSONDecodeError, FileNotFoundError) as e:
        # If reading fails (e.g., empty file), start a new list
        if isinstance(e, (json.JSONDecodeError, FileNotFoundError)) or os.path.getsize(LOG_FILE) == 0:
             with open(LOG_FILE, "w") as f:
                json.dump([event], f, indent=4)
        else:
            logging.error(f"Failed to write to log file {LOG_FILE}: {e}")

# --- LLM Guard Scanners ---
custom_patterns = CONFIG.get("custom_regex_patterns")
if custom_patterns:
    with open(GENERATED_REGEX_FILE, "w") as f:
        json.dump(custom_patterns, f, indent=4)
    logging.info(f"Generated custom regex file at {GENERATED_REGEX_FILE}")
else:
    with open(GENERATED_REGEX_FILE, "w") as f:
        json.dump([], f)
    logging.info("No custom regex patterns found in config. Created empty regex file.")

prompt_injection_scanner = PromptInjection(
    threshold=CONFIG.get("prompt_injection_threshold", 0.90)
)
pii_scanner = Sensitive(
    entity_types=CONFIG.get("pii_entities_to_scan", []),
    redact=CONFIG.get("pii_scan_redact", True),
    threshold=CONFIG.get("pii_scan_threshold", 0.5),
    regex_pattern_groups_path=GENERATED_REGEX_FILE
)

# --- Aegis Security Tools (Generic Middleware) ---
@app.tool()
def analyze_incoming_content(content_to_scan: str) -> Dict[str, Any]:
    """Scans any inbound text for prompt injection attacks."""
    global IS_TAINTED
    # ... (tool logic is unchanged)
    sanitized_content, is_valid, risk_score = prompt_injection_scanner.scan(content_to_scan)
    if not is_valid:
        IS_TAINTED = True
        details = {"original_content": content_to_scan, "reason": "High-risk prompt injection attempt detected."}
        log_event("INJECTION_DETECTED", details, risk_score, "BLOCKED_INPUT")
        return {"status": "SECURITY_ALERT", "action": "BLOCKED_INPUT", "is_valid": False, "risk_score": risk_score, "details": details}
    details = {"scanned_content": content_to_scan}
    log_event("INFO", details, risk_score, "ALLOWED_INPUT")
    return {"status": "SUCCESS", "action": "ALLOWED_INPUT", "is_valid": True, "risk_score": risk_score, "details": "Content scanned and verified."}

@app.tool()
def scan_output_data(data_to_scan: str) -> Dict[str, Any]:
    """Scans any outbound text for sensitive PII."""
    global IS_TAINTED
    # ... (tool logic is unchanged)
    if IS_TAINTED:
        details = {"reason": "Access to data denied because session is tainted."}
        log_event("ACCESS_DENIED", details, 1.0, "DENIED_ACCESS")
        return {"status": "ACCESS_DENIED", "action": "DENIED_ACCESS", "risk_score": 1.0, "details": details}
    sanitized_output, is_valid, risk_score = pii_scanner.scan(prompt="scan", output=data_to_scan)
    if not is_valid:
        details = {"original_data": data_to_scan, "redacted_data": sanitized_output, "reason": "Sensitive PII detected and redacted."}
        log_event("PII_REDACTED", details, risk_score, "REDACTED_OUTPUT")
        return {"status": "SUCCESS_REDACTED", "action": "REDACTED_OUTPUT", "risk_score": risk_score, "sanitized_data": sanitized_output, "details": details}
    log_event("INFO", {"data": data_to_scan}, 0.0, "ALLOWED_OUTPUT")
    return {"status": "SUCCESS", "action": "ALLOWED_OUTPUT", "risk_score": 0.0, "sanitized_data": data_to_scan, "details": "Data scanned and verified."}

@app.tool()
def reset_security_session() -> Dict[str, str]:
    """Resets the session's security state."""
    global IS_TAINTED
    # ... (tool logic is unchanged)
    IS_TAINTED = False
    log_event("ADMIN_ACTION", {"action": "Session reset"}, 0.0, "SESSION_RESET")
    return {"status": "SUCCESS", "message": "Security session has been reset."}

if __name__ == "__main__":
    app.run()