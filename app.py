# app.py
import json
import pandas as pd
import boto3
import logging
import gzip
import io
import plotly.express as px
import streamlit as st
import time
import smtplib
from email.mime.text import MIMEText
from datetime import datetime
from typing import List, Dict, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor
import retrying
import os
import base64
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

# Configure Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# AWS S3 Configuration
S3_BUCKET = "aws-cloudtrail-logs-390844762464-736889dc"
LOG_PREFIX = "AWSLogs/390844762464/CloudTrail/ap-south-1/2025/02"

# Initialize Boto3 S3 Client
s3 = boto3.client(
    "s3",
    aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
    aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
    region_name="ap-south-1"
)

# Functions
@retrying.retry(
    wait_exponential_multiplier=1000,
    wait_exponential_max=10000,
    stop_max_attempt_number=3
)
def list_log_files(bucket: str, prefix: str) -> List[str]:
    response = s3.list_objects_v2(Bucket=bucket, Prefix=prefix)
    files = response.get("Contents", [])
    if not files:
        logger.warning(f"No files found in {bucket}/{prefix}")
        return []
    files.sort(key=lambda x: x["LastModified"], reverse=True)
    return [obj["Key"] for obj in files]

def download_log_file(bucket: str, key: str) -> Dict:
    try:
        log_obj = s3.get_object(Bucket=bucket, Key=key)
        with gzip.GzipFile(fileobj=io.BytesIO(log_obj["Body"].read()), mode="rb") as gz_file:
            log_content = gz_file.read().decode("utf-8")
        return json.loads(log_content)
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in {key}: {e}")
        return {}
    except Exception as e:
        logger.error(f"Error downloading {key}: {e}")
        return {}

def process_logs(log_data: Dict) -> pd.DataFrame:
    events = log_data.get("Records", [])
    if not events:
        logger.warning("No events found in log data.")
        return pd.DataFrame()

    df = pd.json_normalize(events)
    desired_columns = {
        "eventTime": "EventTime",
        "eventName": "EventName",
        "sourceIPAddress": "SourceIP",
        "userIdentity.arn": "User",
        "errorCode": "ErrorCode",  # Renamed to match log structure
        "eventSource": "EventSource",
        "userAgent": "UserAgent"
    }
    available_columns = {col: name for col, name in desired_columns.items() if col in df.columns}
    logger.info(f"Available columns in DataFrame: {list(available_columns.keys())}")
    df = df[list(available_columns.keys())].rename(columns=available_columns)

    if "EventTime" in df.columns:
        df["EventTime"] = pd.to_datetime(df["EventTime"], errors="coerce")
    df.fillna("Unknown", inplace=True)
    return df

def process_multiple_logs(bucket: str, log_keys: List[str]) -> pd.DataFrame:
    with ThreadPoolExecutor(max_workers=4) as executor:
        log_data_list = list(executor.map(lambda key: download_log_file(bucket, key), log_keys))
    dfs = [process_logs(log_data) for log_data in log_data_list if log_data]
    return pd.concat(dfs, ignore_index=True) if dfs else pd.DataFrame()

def analyze_data(df: pd.DataFrame) -> Tuple[Optional[Dict], Optional[pd.DataFrame], Optional[Dict]]:
    if df.empty:
        return None, None, None

    total_events = len(df)
    unique_events = df.get("EventName", pd.Series()).nunique()
    unique_users = df.get("User", pd.Series()).nunique()

    suspicious_ips = None
    security_issues = {}

    if "SourceIP" in df.columns and "EventName" in df.columns:
        # Detect suspicious IPs (e.g., frequent 'GetBucketAcl' calls)
        suspicious_ips = df[df["EventName"] == "GetBucketAcl"]["SourceIP"].value_counts().head()
        if suspicious_ips is not None and len(suspicious_ips) > 5:
            security_issues["ExcessiveBucketAccess"] = {
                "cause": "Multiple IPs are accessing 'GetBucketAcl', indicating potential unauthorized access or bucket misconfiguration.",
                "remedy": "Review S3 bucket policies to ensure private access. Restrict 'GetBucketAcl' to authorized IPs and roles."
            }

    # Detect unauthorized API calls (check if column exists)
    if "ErrorCode" in df.columns:
        unauthorized_events = df[df["ErrorCode"].str.contains("Unauthorized", na=False, case=False)]
        if not unauthorized_events.empty:
            security_issues["UnauthorizedAccess"] = {
                "cause": "Unauthorized API calls detected, possibly due to misconfigured IAM roles or expired credentials.",
                "remedy": "Check IAM policies and rotate credentials. Ensure least privilege principle is applied."
            }
    else:
        logger.warning("Column 'ErrorCode' not found in DataFrame, skipping unauthorized access check.")

    # Detect unusual user agents
    if "UserAgent" in df.columns:
        unusual_agents = df[df["UserAgent"].str.contains("bot|crawler", case=False, na=False)]
        if not unusual_agents.empty:
            security_issues["UnusualActivity"] = {
                "cause": "Unusual user agents (e.g., bots or crawlers) detected, suggesting potential scraping or attack.",
                "remedy": "Implement bot protection (e.g., AWS WAF) and monitor logs for patterns."
            }
    else:
        logger.warning("Column 'UserAgent' not found in DataFrame, skipping unusual activity check.")

    if "EventName" in df.columns and not df["EventName"].empty:
        plot_data = df["EventName"].value_counts().reset_index()
        plot_data.columns = ["EventName", "Count"]
        plot_data = plot_data.nlargest(10, "Count")
        return {
            "total_events": total_events,
            "unique_events": unique_events,
            "unique_users": unique_users,
            "suspicious_ips": suspicious_ips
        }, plot_data, security_issues if security_issues else None
    return None, None, None

# Streamlit App
st.set_page_config(page_title="ThreatLens: AWS CloudTrail Log Analyzer", layout="wide")

# Custom Styling with Updated Background Color
st.markdown(
    """
    <style>
    /* Import Google Fonts */
    @import url('https://fonts.googleapis.com/css2?family=Roboto:wght@400;700&display=swap');

    /* Main App Styling with 3D Effect and New Background */
    .main {
        background: #2f3640;  /* Soft Dark Gray */
        font-family: 'Roboto', sans-serif;
        perspective: 1000px;
    }
    .stApp {
        background: #3b414a;  /* Slightly lighter gray for content area */
        padding: 30px 50px;
        border-radius: 15px;
        box-shadow: 0 20px 30px rgba(0, 0, 0, 0.3), 0 10px 10px rgba(0, 0, 0, 0.1);
        transform: rotateX(5deg) rotateY(5deg);
        transition: transform 0.3s ease;
    }
    .stApp:hover {
        transform: rotateX(0deg) rotateY(0deg) translateZ(10px);
    }
    h1 {
        color: #1f77b4;
        font-size: 2.8em;
        text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.3);
        margin-bottom: 5px;
    }
    .stMarkdown h2 {
        color: #e0e0e0;  /* Lighter text color for contrast */
        font-size: 1.6em;
        text-shadow: 1px 1px 2px rgba(0, 0, 0, 0.2);
        margin-top: 25px;
    }
    .stMarkdown p {
        color: #b0b8c4;  /* Lighter gray for text */
        font-size: 1.1em;
        line-height: 1.7;
    }

    /* Sidebar Styling with 3D Effect */
    .sidebar .sidebar-content {
        padding: 25px;
        background: linear-gradient(145deg, #3b414a, #4a515d);
        border-radius: 15px;
        box-shadow: 0 15px 25px rgba(0, 0, 0, 0.3), inset 0 0 10px rgba(255, 255, 255, 0.2);
        transform: translateZ(5px);
    }
    .sidebar .stSlider, .sidebar .stButton, .sidebar .stSelectbox {
        margin-bottom: 20px;
    }
    .sidebar h3 {
        color: #1f77b4;
        font-size: 1.3em;
        text-shadow: 1px 1px 2px rgba(0, 0, 0, 0.2);
        margin-bottom: 15px;
    }
    .sidebar .stSelectbox div {
        background: linear-gradient(145deg, #4a515d, #5a626f);
        padding: 8px 12px;
        border-radius: 10px;
        box-shadow: 0 5px 10px rgba(0, 0, 0, 0.3), inset 0 0 5px rgba(255, 255, 255, 0.2);
        transition: all 0.3s ease;
        color: #e0e0e0;
    }
    .sidebar .stSelectbox div:hover {
        background: linear-gradient(145deg, #5a626f, #6a727f);
        transform: translateZ(5px);
    }
    .stButton>button {
        background: linear-gradient(145deg, #1f77b4, #2980b9);
        color: white;
        border: none;
        padding: 12px 25px;
        border-radius: 10px;
        box-shadow: 0 8px 15px rgba(0, 0, 0, 0.4), inset 0 0 5px rgba(255, 255, 255, 0.3);
        transition: all 0.3s ease;
        font-weight: bold;
    }
    .stButton>button:hover {
        background: linear-gradient(145deg, #155a8a, #1f77b4);
        transform: translateY(-5px) translateZ(10px);
        box-shadow: 0 12px 20px rgba(0, 0, 0, 0.5), inset 0 0 5px rgba(255, 255, 255, 0.5);
    }
    .stButton>button:active {
        transform: translateY(0) translateZ(0);
        box-shadow: 0 5px 10px rgba(0, 0, 0, 0.3), inset 0 0 5px rgba(0, 0, 0, 0.1);
    }

    /* Loading Spinner */
    .stSpinner {
        position: fixed;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        z-index: 1000;
        background: rgba(59, 65, 74, 0.9);
        padding: 20px;
        border-radius: 10px;
        box-shadow: 0 10px 20px rgba(0, 0, 0, 0.3);
    }

    /* Footer with 3D Effect */
    .stMarkdown footer {
        text-align: center;
        padding: 25px 0;
        color: #b0b8c4;
        font-size: 1em;
        background: linear-gradient(145deg, #3b414a, #4a515d);
        border-radius: 10px;
        box-shadow: 0 10px 20px rgba(0, 0, 0, 0.3), inset 0 0 10px rgba(255, 255, 255, 0.2);
        transform: translateZ(5px);
    }
    .stMarkdown footer a {
        color: #1f77b4;
        text-decoration: none;
        transition: all 0.3s ease;
    }
    .stMarkdown footer a:hover {
        color: #66b0ff;
        text-shadow: 0 0 5px rgba(31, 119, 180, 0.5);
    }

    /* Success and Warning Messages with 3D Effect */
    .stSuccess {
        background: linear-gradient(145deg, #2ecc71, #27ae60);
        color: white;
        padding: 12px;
        border-radius: 10px;
        box-shadow: 0 5px 10px rgba(0, 0, 0, 0.3), inset 0 0 5px rgba(255, 255, 255, 0.5);
    }
    .stWarning {
        background: linear-gradient(145deg, #e74c3c, #c0392b);
        color: white;
        padding: 12px;
        border-radius: 10px;
        box-shadow: 0 5px 10px rgba(0, 0, 0, 0.3), inset 0 0 5px rgba(255, 255, 255, 0.5);
    }
    </style>
    """,
    unsafe_allow_html=True
)

# Logo and Title
st.image("logo.jpeg", width=250, output_format="auto")
st.title("ThreatLens: AWS CloudTrail Log Analyzer")
st.markdown("**Real-Time Security Insights for Your AWS Environment**")

# Sidebar
with st.sidebar:
    st.header("Controls")
    interval = st.slider("Update Interval (seconds)", min_value=10, max_value=60, value=30)
    if st.button("Refresh Data Now"):
        st.session_state.last_update = 0  # Force refresh
    st.header("User Tier")
    user_tier = st.selectbox("Select your tier", ["Free", "Premium"], key="user_tier_select")
    st.header("Pricing")
    st.write("**Free Tier**: Basic analysis and CSV downloads.")
    st.write("**Premium Tier ($10/month)**: Email alerts, PDF reports, and advanced security insights.")
    st.markdown("[Learn More & Sign Up](https://nick1200000.github.io/log-)")
    st.header("Help")
    st.write("Upload CloudTrail logs to your S3 bucket and configure AWS credentials in Streamlit secrets to start analyzing.")
    st.markdown("[Share ThreatLens](https://nick1200000-log-.streamlit.app)")

# Initialize Session State
if "processed_keys" not in st.session_state:
    st.session_state.processed_keys = set()
if "df" not in st.session_state:
    st.session_state.df = pd.DataFrame()
if "last_update" not in st.session_state:
    st.session_state.last_update = time.time()

# Update Data with Loading Spinner
if st.session_state.last_update == 0 or (time.time() - st.session_state.last_update >= interval):
    with st.spinner("Processing new log files..."):
        log_files = list_log_files(S3_BUCKET, LOG_PREFIX)
        if log_files:
            new_log_files = [key for key in log_files if key not in st.session_state.processed_keys]
            if new_log_files:
                st.write(f"Found {len(new_log_files)} new log files. Processing...")
                new_df = process_multiple_logs(S3_BUCKET, new_log_files)
                st.session_state.df = pd.concat([st.session_state.df, new_df], ignore_index=True)
                st.session_state.processed_keys.update(new_log_files)
            else:
                st.write("No new log files to process. Waiting for new logs...")
        else:
            st.write("No log files found in the specified S3 bucket.")
        st.session_state.last_update = time.time()

# Analyze Data
summary, plot_data, security_issues = analyze_data(st.session_state.df)
if summary:
    st.subheader("📊 Analysis Summary")
    st.write(f"**Total Events Processed:** {summary['total_events']}")
    st.write(f"**Unique Event Types:** {summary['unique_events']}")
    st.write(f"**Unique Users:** {summary['unique_users']}")
    if summary["suspicious_ips"] is not None:
        st.subheader("⚠️ Potential Security Concern")
        st.write("Top IPs making 'GetBucketAcl' calls:")
        st.write(summary["suspicious_ips"])
        if user_tier == "Premium" and len(summary["suspicious_ips"]) > 5:
            st.warning("⚠️ High number of suspicious IPs detected!")
            msg = MIMEText(f"Suspicious activity detected: {summary['suspicious_ips'].to_string()}")
            msg["Subject"] = "ThreatLens Security Alert"
            msg["From"] = os.getenv("EMAIL_USER")
            msg["To"] = os.getenv("EMAIL_USER")
            with smtplib.SMTP("smtp.gmail.com", 587) as server:
                server.starttls()
                server.login(os.getenv("EMAIL_USER"), os.getenv("EMAIL_PASSWORD"))
                server.send_message(msg)
            st.success("Alert sent to your email!")
        elif user_tier == "Free":
            st.info("Upgrade to Premium to receive email alerts for suspicious activity!")

    st.subheader("📈 Top 10 Event Types")
    fig = px.bar(
        plot_data,
        y="EventName",
        x="Count",
        orientation="h",
        title="Top 10 Event Types in CloudTrail Logs",
        color="EventName",
        color_discrete_sequence=px.colors.sequential.Viridis
    )
    fig.update_layout(showlegend=False, xaxis_title="Count", yaxis_title="Event Name")
    st.plotly_chart(fig)

    # Display Security Issues and Remedies (Premium Feature)
    if user_tier == "Premium" and security_issues:
        st.subheader("🔍 Security Issues & Remedies")
        for issue_type, details in security_issues.items():
            st.markdown(f"**{issue_type.replace('_', ' ').title()}**")
            st.write(f"**Cause:** {details['cause']}")
            st.write(f"**Remedy:** {details['remedy']}")
            st.markdown("---")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    st.session_state.df.to_csv(f"processed_cloudtrail_logs_{timestamp}.csv", index=False)
    st.write(f"Data saved as 'processed_cloudtrail_logs_{timestamp}.csv'.")
    csv = st.session_state.df.to_csv(index=False)
    b64 = base64.b64encode(csv.encode()).decode()
    href = f'<a href="data:file/csv;base64,{b64}" download="cloudtrail_logs_{timestamp}.csv">Download CSV</a>'
    st.markdown(href, unsafe_allow_html=True)

    if user_tier == "Premium":
        pdf_buffer = io.BytesIO()
        doc = SimpleDocTemplate(pdf_buffer, pagesize=letter)
        styles = getSampleStyleSheet()
        content = [
            Paragraph(f"ThreatLens Report - {datetime.now().strftime('%Y-%m-%d')}", styles['Title']),
            Spacer(1, 12),
            Paragraph(f"Total Events: {summary['total_events']}", styles['Normal']),
            Paragraph(f"Unique Event Types: {summary['unique_events']}", styles['Normal']),
            Paragraph(f"Unique Users: {summary['unique_users']}", styles['Normal']),
            Paragraph("Suspicious IPs: " + (summary["suspicious_ips"].to_string() if summary["suspicious_ips"] is not None else "None"), styles['Normal'])
        ]
        if security_issues:
            for issue_type, details in security_issues.items():
                content.append(Paragraph(f"{issue_type.replace('_', ' ').title()}", styles['Heading2']))
                content.append(Paragraph(f"Cause: {details['cause']}", styles['Normal']))
                content.append(Paragraph(f"Remedy: {details['remedy']}", styles['Normal']))
                content.append(Spacer(1, 12))
        doc.build(content)
        st.download_button(
            label="Download PDF Report",
            data=pdf_buffer.getvalue(),
            file_name=f"cloudtrail_report_{timestamp}.pdf",
            mime="application/pdf"
        )
    else:
        st.info("Upgrade to Premium to download PDF reports and access advanced security insights!")
else:
    st.write("No data to analyze yet. Waiting for logs...")

# Auto-refresh
st.write(f"Next update in {max(0, interval - int(time.time() - st.session_state.last_update))} seconds...")
if time.time() - st.session_state.last_update >= interval:
    st.rerun()

# Footer
st.markdown(
    """
    <div style="text-align: center; padding: 25px 0; color: #b0b8c4; font-size: 1em; background: linear-gradient(145deg, #3b414a, #4a515d); border-radius: 10px; box-shadow: 0 10px 20px rgba(0, 0, 0, 0.3), inset 0 0 10px rgba(255, 255, 255, 0.2); transform: translateZ(5px);">
        **ThreatLens** | © 2025 | 
        <a href="mailto:your-email@example.com" style="color: #1f77b4; text-decoration: none; transition: all 0.3s ease;">Contact Us</a>  
        <br>This app processes your logs in real-time and does not store data unless explicitly saved.
    </div>
    """,
    unsafe_allow_html=True
)
