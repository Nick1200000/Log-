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
from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor
import retrying
import os
import base64
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
import streamlit_authenticator as stauth
import yaml
from yaml.loader import SafeLoader

# Configure Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Load Authentication Config
with open('config.yaml') as file:
    config = yaml.load(file, Loader=SafeLoader)

authenticator = stauth.Authenticate(
    config['credentials'],
    config['cookie']['name'],
    config['cookie']['key'],
    config['cookie']['expiry_days'],
    config['preauthorized']
)

# Authentication
name, authentication_status, username = authenticator.login('Login', 'main')

if authentication_status:
    authenticator.logout('Logout', 'sidebar')
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

    # Functions (same as before)
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
            "errorCode": "Error"
        }
        available_columns = {col: name for col, name in desired_columns.items() if col in df.columns}
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

    def analyze_data(df: pd.DataFrame) -> tuple:
        if df.empty:
            return None, None

        total_events = len(df)
        unique_events = df.get("EventName", pd.Series()).nunique()
        unique_users = df.get("User", pd.Series()).nunique()

        suspicious_ips = None
        if "SourceIP" in df.columns and "EventName" in df.columns:
            suspicious_ips = df[df["EventName"] == "GetBucketAcl"]["SourceIP"].value_counts().head()

        if "EventName" in df.columns and not df["EventName"].empty:
            plot_data = df["EventName"].value_counts().reset_index()
            plot_data.columns = ["EventName", "Count"]
            plot_data = plot_data.nlargest(10, "Count")
            return {
                "total_events": total_events,
                "unique_events": unique_events,
                "unique_users": unique_users,
                "suspicious_ips": suspicious_ips
            }, plot_data
        return None, None

    # Streamlit App
    st.set_page_config(page_title="ThreatLens: AWS CloudTrail Log Analyzer", layout="wide")

    # Custom Styling
    st.markdown(
        """
        <style>
        .main {
            background-color: #f0f2f6;
        }
        .stApp {
            background-color: #ffffff;
            padding: 20px;
            border-radius: 10px;
        }
        h1 {
            color: #1f77b4;
        }
        </style>
        """,
        unsafe_allow_html=True
    )

    st.image("logo.jpeg", width=200)  # Updated to logo.jpeg
    st.title("ThreatLens: AWS CloudTrail Log Analyzer")
    st.write("Secure your AWS environment with real-time CloudTrail insights!")

    # Sidebar
    st.sidebar.header("Controls")
    interval = st.sidebar.slider("Update Interval (seconds)", min_value=10, max_value=60, value=30)
    refresh_button = st.sidebar.button("Refresh Data Now")
    st.sidebar.header("User Tier")
    user_tier = st.sidebar.selectbox("Select your tier", ["Free", "Premium"])
    st.sidebar.header("Pricing")
    st.sidebar.write("**Free Tier**: Basic analysis and CSV downloads.")
    st.sidebar.write("**Premium Tier ($10/month)**: Email alerts, PDF reports, and priority support.")
    st.sidebar.markdown("[Learn More & Sign Up](https://nick1200000.github.io/log-)")  # Replace with your GitHub Pages URL
    st.sidebar.header("Help")
    st.sidebar.write("Upload CloudTrail logs to your S3 bucket and configure AWS credentials in Streamlit secrets to start analyzing.")
    st.sidebar.markdown("[Share ThreatLens](https://nick1200000-log-.streamlit.app)")

    # Initialize Session State
    if "processed_keys" not in st.session_state:
        st.session_state.processed_keys = set()
    if "df" not in st.session_state:
        st.session_state.df = pd.DataFrame()
    if "last_update" not in st.session_state:
        st.session_state.last_update = time.time()

    # Update Data
    if refresh_button or (time.time() - st.session_state.last_update >= interval):
        log_files = list_log_files(S3_BUCKET, LOG_PREFIX)
        if log_files:
            new_log_files = [key for key in log_files if key not in st.session_state.processed_keys]
            if new_log_files:
                st.write(f"Found {len(new_log_files)} new log files. Processing...")
                new_df = process_multiple_logs(S3_BUCKET, new_log_files)
                st.session_state.df = pd.concat([st.session_state.df, new_df], ignore_index=True)
                st.session_state.processed_keys.update(new_log_files)
                st.session_state.last_update = time.time()
            else:
                st.write("No new log files to process. Waiting for new logs...")
        else:
            st.write("No log files found in the specified S3 bucket.")

    # Analyze Data
    summary, plot_data = analyze_data(st.session_state.df)
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
            doc.build(content)
            st.download_button(
                label="Download PDF Report",
                data=pdf_buffer.getvalue(),
                file_name=f"cloudtrail_report_{timestamp}.pdf",
                mime="application/pdf"
            )
        else:
            st.info("Upgrade to Premium to download PDF reports!")
    else:
        st.write("No data to analyze yet. Waiting for logs...")

    # Auto-refresh
    st.write(f"Next update in {max(0, interval - int(time.time() - st.session_state.last_update))} seconds...")
    if time.time() - st.session_state.last_update >= interval:
        st.rerun()

    # Footer
    st.markdown(
        """
        ---
        **ThreatLens** | © 2025 | [Contact Us](mailto:your-email@example.com)  
        This app processes your logs in real-time and does not store data unless explicitly saved.
        """
    )

elif authentication_status == False:
    st.error('Username/password is incorrect')
elif authentication_status == None:
    st.warning('Please enter your username and password')
