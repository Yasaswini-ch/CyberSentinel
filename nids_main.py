import streamlit as st
import pandas as pd 
import numpy as np 
from sklearn.ensemble import RandomForestClassifier 
from sklearn.model_selection import train_test_split 
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score 
import seaborn as sns
import matplotlib.pyplot as plt
import time
import smtplib
import ssl
from email.message import EmailMessage
# --- PAGE CONFIGURATION --- 
st.set_page_config(page_title="CyberSentinel", layout="wide")
# Custom Title and Description
st.title("CyberSentinel")
st.markdown("""
### Project Overview

CyberSentinel is an experimental, extensible Network Intrusion Detection System (NIDS) prototype that demonstrates how machine learning can be applied to streaming network telemetry to detect anomalous and malicious traffic. The dashboard provides:

- Real-time traffic ingestion and synthetic traffic generation for testing.
- A supervised ML pipeline (Random Forest) trained on engineered flow-level features.
- Live visualizations to monitor packet flow, detection rates, and attack category trends.
- An alerting subsystem (in-app and optional email) for immediate notifications on suspicious activity.
- Interactive logs with filtering by source IP, protocol, and attack type for rapid triage.

This project is intended as a research and demonstration tool: it shows architectural patterns (feature engineering, model training, streaming inference, alerting, and dashboards) and is easily adaptable to real network feeds (pcap, NetFlow, streaming telemetry) and production-grade models. It is not a production security appliance — evaluate and harden before operational use.
""")
# --- 1. DATA LOADING (Simulation or Real) --- 
@st.cache_data 
def load_data(): 
    """ 
    Generates a synthetic dataset that mimics network traffic logs (CIC-IDS2017 structure). 
    In a real deployment, this would be replaced by pd.read_csv('network_logs.csv'). 
    """ 
    np.random.seed(42) 
    n_samples = 5000 
     
    # Simulating features common in Network Logs 
    data = { 
        'Destination_Port': np.random.randint(1, 65535, n_samples), 
        'Flow_Duration': np.random.randint(100, 100000, n_samples), 
        'Total_Fwd_Packets': np.random.randint(1, 100, n_samples), 
        'Packet_Length_Mean': np.random.uniform(10, 1500, n_samples), 
        'Active_Mean': np.random.uniform(0, 1000, n_samples), 
        'Label': np.random.choice([0, 1], size=n_samples, p=[0.7, 0.3]) # 0=Safe, 1=Attack 
    } 
     
    df = pd.DataFrame(data)

    # Add metadata useful for dashboard and interactive logs
    df['Source_IP'] = np.random.choice([
        '192.168.1.' + str(i) for i in range(2, 255)
    ], size=n_samples)
    df['Protocol'] = np.random.choice(['TCP', 'UDP', 'ICMP', 'HTTP'], size=n_samples, p=[0.5, 0.2, 0.1, 0.2])
    # Assign attack type for malicious rows
    attack_types = ['DDoS', 'PortScan', 'BruteForce', 'Botnet']
    df['Attack_Type'] = np.where(df['Label'] == 1, np.random.choice(attack_types, size=n_samples), 'Benign')

    # Introduce patterns for the AI to learn
    # E.g., Attacks (Label 1) usually have very high packet counts or very short duration
    df.loc[df['Label'] == 1, 'Total_Fwd_Packets'] += np.random.randint(50, 200, 
size=df[df['Label']==1].shape[0]) 
    df.loc[df['Label'] == 1, 'Flow_Duration'] = np.random.randint(1, 1000, 
size=df[df['Label']==1].shape[0]) 
     
    return df 
# Load Data 
df = load_data() 
# Sidebar Controls
st.sidebar.header("Control Panel")
st.sidebar.info("Adjust model parameters here.")
split_size = st.sidebar.slider("Training Data Size (%)", 50, 90, 80) 
n_estimators = st.sidebar.slider("Number of Trees (Random Forest)", 10, 200, 100) 
# --- 2. PREPROCESSING & SPLIT --- 
X = df[['Destination_Port', 'Flow_Duration', 'Total_Fwd_Packets', 'Packet_Length_Mean', 'Active_Mean']]
y = df['Label'] 
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=(100-split_size)/100, 
random_state=42) 
# --- 3. MODEL TRAINING --- 
st.divider() 
col_train, col_metrics = st.columns([1, 2]) 
with col_train:
    st.subheader("1. Model Training")
    if st.button("Train Model Now"):
        with st.spinner("Training Random Forest Classifier..."):
            # Initialize and train the model
            model = RandomForestClassifier(n_estimators=n_estimators)
            model.fit(X_train, y_train)
            st.session_state['model'] = model  # Save model to session
            st.success("Training Complete!")

    if 'model' in st.session_state:
        st.success("Model is Ready for Testing")
 
# --- 4. EVALUATION METRICS --- 
with col_metrics: 
    st.subheader("2. Performance Metrics") 
    if 'model' in st.session_state: 
        model = st.session_state['model'] 
        y_pred = model.predict(X_test) 
        acc = accuracy_score(y_test, y_pred) 
         
        m1, m2, m3 = st.columns(3) 
        m1.metric("Accuracy", f"{acc*100:.2f}%") 
        m2.metric("Total Samples", len(df)) 
        m3.metric("Detected Threats", np.sum(y_pred)) 
         
        # Visualization: Confusion Matrix 
        st.write("### Confusion Matrix") 
        cm = confusion_matrix(y_test, y_pred) 
        fig, ax = plt.subplots(figsize=(4, 2)) 
        sns.heatmap(cm, annot=True, fmt='d', cmap='Reds', ax=ax) 
        st.pyplot(fig) 
        # Gamified security score and threat-intel matching
        alerts_count = len(st.session_state.get('alerts', []))
        security_score = max(0, 100 - alerts_count * 5)
        if security_score >= 90:
            badge = '🥇 Gold'
        elif security_score >= 70:
            badge = '🥈 Silver'
        else:
            badge = '🥉 Bronze'
        st.markdown(f"**Security Score:** {security_score} — {badge}")

        # Simple local threat-intel mapping (demo). Replace with live feeds in production.
        def get_threat_matches(logs_df):
            mapping = {
                'DDoS': ['T1499 (Endpoint DoS)'],
                'PortScan': ['T1595 (Active Scanning)'],
                'BruteForce': ['T1110 (Brute Force)'],
                'Botnet': ['T1587 (Botnet)']
            }
            matches = {}
            if logs_df is None or logs_df.empty:
                return matches
            alerts_df = logs_df[logs_df['pred'] == 1]
            for atype in alerts_df['Attack_Type'].dropna().unique():
                matches[atype] = mapping.get(atype, ['Unknown'])
            return matches

        matches = get_threat_matches(st.session_state.get('logs', pd.DataFrame()))
        if matches:
            st.write('### Threat Intelligence Matches (local demo)')
            for k, v in matches.items():
                st.write(f'- **{k}**: {", ".join(v)}')
    else: 
        st.warning("Please train the model first.") 
 
# --- 5. LIVE ATTACK SIMULATOR --- 
st.divider() 
st.subheader("3. Live Traffic Simulator (Test the AI)") 
 
st.write("Enter network packet details below to see if the AI flags it as an attack.") 
 
c1, c2, c3, c4 = st.columns(4)
p_dur = c1.number_input("Flow Duration (ms)", 0, 100000, 500)
p_pkts = c2.number_input("Total Packets", 0, 500, 100)
p_len = c3.number_input("Packet Length Mean", 0, 1500, 500)
p_active = c4.number_input("Active Mean Time", 0, 1000, 50)
src_ip = c1.text_input("Source IP", value="192.168.1.10")
protocol = c2.selectbox("Protocol", options=['TCP', 'UDP', 'ICMP', 'HTTP'])
dest_port = c3.number_input("Destination Port", 1, 65535, 80)

# Email alert configuration in sidebar
st.sidebar.markdown('**Alerting Configuration**')
smtp_server = st.sidebar.text_input('SMTP Server', value='')
smtp_port = st.sidebar.number_input('SMTP Port', value=587)
smtp_user = st.sidebar.text_input('SMTP User', value='')
smtp_pass = st.sidebar.text_input('SMTP Password', type='password')
recipient = st.sidebar.text_input('Alert Recipient Email', value='')
if smtp_server and smtp_user and smtp_pass and recipient:
    st.session_state['email_configured'] = True
    st.session_state['email_config'] = {
        'smtp_server': smtp_server,
        'smtp_port': smtp_port,
        'smtp_user': smtp_user,
        'smtp_pass': smtp_pass,
        'recipient': recipient,
    }
else:
    st.session_state['email_configured'] = False


def send_email_alert(smtp_server, smtp_port, smtp_user, smtp_pass, recipient, subject, body):
    msg = EmailMessage()
    msg.set_content(body)
    msg['Subject'] = subject
    msg['From'] = smtp_user
    msg['To'] = recipient

    if smtp_port == 465:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(smtp_server, smtp_port, context=context) as server:
            server.login(smtp_user, smtp_pass)
            server.send_message(msg)
    else:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.send_message(msg)


if 'logs' not in st.session_state:
    st.session_state['logs'] = pd.DataFrame(columns=[
        'timestamp', 'Source_IP', 'Destination_Port', 'Protocol', 'Flow_Duration',
        'Total_Packets', 'Packet_Length_Mean', 'Active_Mean', 'pred', 'Attack_Type'
    ])

if 'alerts' not in st.session_state:
    st.session_state['alerts'] = []

if st.button("Analyze Packet"):
    if 'model' in st.session_state:
        model = st.session_state['model']
        input_data = np.array([[dest_port, p_dur, p_pkts, p_len, p_active]])
        pred = int(model.predict(input_data)[0])

        new_row = {
            'timestamp': pd.Timestamp.now(),
            'Source_IP': src_ip,
            'Destination_Port': dest_port,
            'Protocol': protocol,
            'Flow_Duration': p_dur,
            'Total_Packets': p_pkts,
            'Packet_Length_Mean': p_len,
            'Active_Mean': p_active,
            'pred': pred,
            'Attack_Type': 'Unknown' if pred == 1 else 'Benign'
        }
        st.session_state['logs'] = pd.concat([st.session_state['logs'], pd.DataFrame([new_row])], ignore_index=True)

        if pred == 1:
            st.error("ALERT: MALICIOUS TRAFFIC DETECTED!")
            st.write("**Reason:** High packet count with low duration is suspicious.")
            st.session_state['alerts'].append(new_row)
            if st.session_state.get('email_configured'):
                try:
                    cfg = st.session_state['email_config']
                    send_email_alert(
                        smtp_server=cfg['smtp_server'],
                        smtp_port=cfg['smtp_port'],
                        smtp_user=cfg['smtp_user'],
                        smtp_pass=cfg['smtp_pass'],
                        recipient=cfg['recipient'],
                        subject='NIDS Alert: Malicious Traffic Detected',
                        body=f"Detected malicious traffic from {src_ip} at {pd.Timestamp.now()}\nDetails: {new_row}"
                    )
                    st.info('Email alert sent.')
                except Exception as e:
                    st.warning(f'Failed to send email alert: {e}')
        else:
            st.success("Traffic Status: BENIGN (Safe)")
    else:
        st.error("Please train the model first!")


# --- Dashboard Enhancements: Visualizations, Logs, Generators ---
st.divider()
st.subheader('Live Visualizations & Interactive Logs')

# Controls for generating packets in bulk from the synthetic dataset
gen_col1, gen_col2 = st.columns([2, 1])
with gen_col1:
    gen_n = st.number_input('Generate N random packets', min_value=1, max_value=200, value=5)
    if st.button('Generate Random Packets'):
        for _ in range(gen_n):
            row = df.sample(1).iloc[0].to_dict()
            if 'model' in st.session_state:
                model = st.session_state['model']
                input_data = np.array([[row['Destination_Port'], row['Flow_Duration'], row['Total_Fwd_Packets'], row['Packet_Length_Mean'], row['Active_Mean']]])
                pred = int(model.predict(input_data)[0])
            else:
                pred = None
            new_row = {
                'timestamp': pd.Timestamp.now(),
                'Source_IP': row.get('Source_IP', '0.0.0.0'),
                'Destination_Port': row['Destination_Port'],
                'Protocol': row.get('Protocol', 'TCP'),
                'Flow_Duration': row['Flow_Duration'],
                'Total_Packets': row['Total_Fwd_Packets'],
                'Packet_Length_Mean': row['Packet_Length_Mean'],
                'Active_Mean': row['Active_Mean'],
                'pred': pred,
                'Attack_Type': row.get('Attack_Type', 'Benign')
            }
            st.session_state['logs'] = pd.concat([st.session_state['logs'], pd.DataFrame([new_row])], ignore_index=True)
            if pred == 1:
                st.session_state['alerts'].append(new_row)
        st.success(f'Generated {gen_n} packets.')

# Visualizations
vis_col1, vis_col2 = st.columns(2)
with vis_col1:
    st.markdown('**Packet Flow (Total Packets over Time)**')
    if not st.session_state['logs'].empty:
        lf = st.session_state['logs'].copy()
        # ensure timestamp and numeric columns
        lf['ts'] = pd.to_datetime(lf['timestamp'])
        # Coerce packet and prediction columns to numeric safely
        if 'Total_Packets' in lf.columns:
            lf['Total_Packets'] = pd.to_numeric(lf['Total_Packets'], errors='coerce').fillna(0)
        elif 'Total_Fwd_Packets' in lf.columns:
            lf['Total_Packets'] = pd.to_numeric(lf['Total_Fwd_Packets'], errors='coerce').fillna(0)
        else:
            # create a default zero column if nothing available
            lf['Total_Packets'] = 0

        lf['pred'] = pd.to_numeric(lf.get('pred', 0), errors='coerce').fillna(0).astype(int)

        # Resample and sum packet counts
        res = lf.set_index('ts').resample('5S').sum(numeric_only=True)
        if 'Total_Packets' in res.columns:
            flow = res['Total_Packets'].fillna(0)
        else:
            flow = pd.Series(dtype=float)
        st.line_chart(flow)
    else:
        st.info('No logs yet. Generate or analyze packets to populate live charts.')

with vis_col2:
    st.markdown('**Detection Rate (rolling)**')
    if not st.session_state['logs'].empty:
        lf = st.session_state['logs'].copy()
        lf['ts'] = pd.to_datetime(lf['timestamp'])
        lf['pred'] = pd.to_numeric(lf.get('pred', 0), errors='coerce').fillna(0).astype(int)
        # Resample into 5-second buckets and compute detection rate = detections / total
        df_res = lf.set_index('ts').resample('5S').agg(total=('pred', 'size'), detections=('pred', 'sum'))
        # Avoid division by zero
        df_res['rate'] = (df_res['detections'] / df_res['total']).fillna(0)
        st.line_chart(df_res['rate'])
    else:
        st.info('No logs yet.')

st.markdown('**Attack Categories**')
if not st.session_state['logs'].empty:
    cat = st.session_state['logs'][st.session_state['logs']['pred'] == 1]['Attack_Type'].value_counts()
    st.bar_chart(cat)
else:
    st.info('No attack data yet.')

# Interactive Logs with filters
st.markdown('**Interactive Logs**')
logs = st.session_state['logs']
filter_col1, filter_col2, filter_col3 = st.columns(3)
with filter_col1:
    f_ip = st.text_input('Filter Source IP', value='')
with filter_col2:
    protocols = ['All'] + sorted(logs['Protocol'].dropna().unique().tolist()) if not logs.empty else ['All']
    f_proto = st.selectbox('Protocol', options=protocols)
with filter_col3:
    types = ['All'] + sorted(logs['Attack_Type'].dropna().unique().tolist()) if not logs.empty else ['All']
    f_type = st.selectbox('Attack Type', options=types)

fdf = logs.copy()
if f_ip:
    fdf = fdf[fdf['Source_IP'].str.contains(f_ip, na=False)]
if f_proto and f_proto != 'All':
    fdf = fdf[fdf['Protocol'] == f_proto]
if f_type and f_type != 'All':
    fdf = fdf[fdf['Attack_Type'] == f_type]

# Show full interactive logs to all users
st.dataframe(fdf.sort_values('timestamp', ascending=False).reset_index(drop=True))
 