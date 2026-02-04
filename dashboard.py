
import streamlit as st
import pandas as pd
import json
import time
from pathlib import Path

# --- Page Configuration ---
st.set_page_config(
    page_title="Aegis Security Dashboard",
    page_icon="🛡️",
    layout="wide",
)

# --- Dashboard Title ---
st.title("🛡️ Aegis: Anti Gen-AI Defense Dashboard")
st.caption("Real-time monitoring of the Aegis Generic Security Middleware.")

# --- Helper Functions ---
LOG_FILE = Path("security_events.json")

def load_data():
    """Loads and processes security events from the JSON log file."""
    if not LOG_FILE.exists() or LOG_FILE.stat().st_size < 5:  # Check for empty or near-empty file
        return pd.DataFrame()

    try:
        # Load the entire list of JSON objects from the file
        with open(LOG_FILE, "r") as f:
            data = json.load(f)
        
        if not data:
            return pd.DataFrame()

        df = pd.DataFrame(data)

        # Normalize the 'details' column which contains nested JSON objects
        # This will create new columns like 'details.reason', 'details.original_content', etc.
        details_normalized = pd.json_normalize(df['details'], max_level=1).add_prefix('details.')
        
        # Drop the original 'details' column and join the new flattened columns
        df = df.drop('details', axis=1).join(details_normalized)

        # Convert timestamp to datetime and format it
        if "timestamp" in df.columns:
            df["timestamp"] = pd.to_datetime(df["timestamp"]).dt.strftime('%Y-%m-%d %H:%M:%S')
        
        return df
    
    except (json.JSONDecodeError, ValueError, FileNotFoundError) as e:
        # Display an error in the dashboard if the log file is corrupt
        st.error(f"Error loading or parsing log file: {e}")
        return pd.DataFrame()

def style_rows(row):
    """Applies color coding to rows based on the action taken."""
    if "action" not in row:
        return [""] * len(row)
    action = row["action"]
    if "BLOCKED" in action or "DENIED" in action:
        color = "background-color: #ff4d4d; color: white;"  # Red
    elif "REDACTED" in action:
        color = "background-color: #ffcc00;"  # Yellow
    elif "RESET" in action:
        color = "background-color: #00bfff; color: white;" # Blue
    elif "ALLOWED" in action:
        color = "background-color: #4CAF50; color: white;"  # Green
    else:
        color = ""
    return [color] * len(row)

# --- Main Dashboard Area ---
placeholder = st.empty()

# --- Auto-Refresh Loop ---
while True:
    df = load_data()

    with placeholder.container():
        # --- KPI Metrics ---
        if not df.empty and "action" in df.columns:
            total_events = len(df)
            injections_blocked = df[df["action"] == "BLOCKED_INPUT"].shape[0]
            pii_leaks_prevented = df[df["action"] == "REDACTED_OUTPUT"].shape[0]
            access_denials = df[df["action"] == "DENIED_ACCESS"].shape[0]
        else:
            total_events, injections_blocked, pii_leaks_prevented, access_denials = 0, 0, 0, 0

        kpi1, kpi2, kpi3, kpi4 = st.columns(4)
        kpi1.metric(label="🛡️ Total Events", value=total_events)
        kpi2.metric(label="🚨 Injections Blocked", value=injections_blocked)
        kpi3.metric(label="🔒 PII Leaks Prevented", value=pii_leaks_prevented)
        kpi4.metric(label="❌ Access Denied", value=access_denials)

        st.markdown("---")

        # --- Live Audit Log ---
        st.subheader("Live Audit Log")
        if not df.empty:
            # Define which columns to display for a cleaner look
            # The full, detailed log is still available if needed
            display_columns = [
                "timestamp", "event_type", "action", "risk_score", 
                "details.reason", "details.original_content", "details.redacted_data"
            ]
            # Filter down to only the columns that actually exist in the dataframe
            existing_display_columns = [col for col in display_columns if col in df.columns]

            st.dataframe(
                df[existing_display_columns].style.apply(style_rows, axis=1),
                use_container_width=True,
                height=500
            )
        else:
            st.info("No security events logged yet. Start the MCP server and interact with the agent.")

    time.sleep(2)
