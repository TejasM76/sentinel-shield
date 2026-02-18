"""
Streamlit dashboard for SentinelShield AI Security Platform
Professional real-time security monitoring interface
"""

import streamlit as st
import requests
import json
import time
from datetime import datetime

try:
    import pandas as pd
    import numpy as np
    import plotly.express as px
    import plotly.graph_objects as go
except ImportError:
    pd = None
    np = None
    px = None
    go = None

# Set page configuration
st.set_page_config(
    page_title="SentinelShield AI Security Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
.main-header {
    font-size: 2.5rem;
    font-weight: bold;
    color: #2E86AB;
    text-align: center;
    margin-bottom: 2rem;
}
.metric-card {
    background: #f8f9fa;
    padding: 1rem;
    border-radius: 10px;
    border-left: 4px solid #2E86AB;
    margin: 0.5rem 0;
}
.status-healthy { color: #28a745; font-weight: bold; }
.status-warning { color: #ffc107; font-weight: bold; }
.status-danger { color: #dc3545; font-weight: bold; }
</style>
""", unsafe_allow_html=True)

# Header
st.markdown('<div class="main-header">🛡️ SentinelShield AI Security Platform</div>', unsafe_allow_html=True)

# Sidebar Navigation
st.sidebar.markdown("### 🗂️ Navigation")
page = st.sidebar.radio(
    "Select Page",
    [
        "🏠 Security Operations Center",
        "🔴 Red Team Testing Lab",
        "🤖 Agent Security Monitor",
        "📊 Compliance Dashboard",
        "🧠 Threat Intelligence",
        "⚙️ Settings"
    ],
    label_visibility="collapsed"
)

st.sidebar.markdown("---")

# API Configuration
st.sidebar.markdown("### 🔧 API Configuration")
api_url = st.sidebar.text_input("API URL", value="http://localhost:8001", help="SentinelShield API endpoint")

# Check API Health
try:
    health_response = requests.get(f"{api_url}/health", timeout=5)
    if health_response.status_code == 200:
        health_data = health_response.json()
        st.sidebar.markdown(f'<div class="status-healthy">✅ API Status: {health_data["status"]}</div>', unsafe_allow_html=True)
        st.sidebar.markdown(f"📊 OWASP Coverage: {health_data.get('owasp_coverage', 'Unknown')}")
    else:
        st.sidebar.markdown('<div class="status-danger">❌ API Connection Failed</div>', unsafe_allow_html=True)
except Exception as e:
    st.sidebar.markdown('<div class="status-danger">❌ API Error</div>', unsafe_allow_html=True)
    st.sidebar.error(f"Error: {str(e)}")

# Main Interface
st.markdown("## 🎯 Threat Scanner")

# Input Section
col1, col2 = st.columns([3, 1])

with col1:
    prompt = st.text_area(
        "Enter Prompt to Scan:",
        placeholder="Enter a prompt to analyze for security threats...",
        height=100,
        help="Enter any prompt or text that you want to analyze for potential security threats"
    )

with col2:
    st.markdown("<br>", unsafe_allow_html=True)
    if st.button("🔍 Scan Prompt", type="primary", use_container_width=True):
        if prompt:
            # Scan the prompt
            with st.spinner("🔍 Analyzing prompt..."):
                try:
                    scan_response = requests.post(
                        f"{api_url}/scan",
                        json={"prompt": prompt, "client_id": "dashboard"},
                        timeout=10
                    )

                    if scan_response.status_code == 200:
                        result = scan_response.json()

                        # Store results in session state
                        st.session_state.scan_result = result
                        st.session_state.scan_timestamp = datetime.now().isoformat()

                    else:
                        st.error(f"❌ Scan failed: {scan_response.status_code}")
                        st.session_state.scan_result = None

                except Exception as e:
                    st.error(f"❌ Connection error: {str(e)}")
                    st.session_state.scan_result = None
        else:
            st.warning("⚠️ Please enter a prompt to scan")

# Display Results
if hasattr(st.session_state, 'scan_result') and st.session_state.scan_result:
    result = st.session_state.scan_result

    st.markdown("## 📊 Scan Results")

    # Decision Status
    decision = result.get('decision', 'UNKNOWN')
    risk_score = result.get('risk_score', 0.0)
    threats = result.get('threats_detected', [])

    # Status Color
    if decision == "BLOCK":
        status_color = "status-danger"
        status_icon = "🚫"
    elif decision == "REVIEW":
        status_color = "status-warning"
        status_icon = "⚠️"
    else:
        status_color = "status-healthy"
        status_icon = "✅"

    # Main Status Card
    col1, col2, col3 = st.columns(3)

    with col1:
        st.markdown(f"""
        <div class="metric-card">
            <h3>{status_icon} Decision</h3>
            <h2 class="{status_color}">{decision}</h2>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown(f"""
        <div class="metric-card">
            <h3>📈 Risk Score</h3>
            <h2>{risk_score:.2f}</h2>
        </div>
        """, unsafe_allow_html=True)

    with col3:
        st.markdown(f"""
        <div class="metric-card">
            <h3>🎯 Threats Found</h3>
            <h2>{len(threats)}</h2>
        </div>
        """, unsafe_allow_html=True)

    # Detailed Results
    if threats:
        st.markdown("### 🚨 Detected Threats")

        for threat in threats:
            st.markdown(f"- **{threat}**")
    else:
        st.markdown("### ✅ No Threats Detected")
        st.info("No security threats were detected in this prompt.")

    # Technical Details
    with st.expander("🔧 Technical Details"):
        col1, col2 = st.columns(2)

        with col1:
            st.markdown(f"**Request ID:** `{result.get('request_id', 'N/A')}`")
            st.markdown(f"**Timestamp:** `{result.get('timestamp', 'N/A')}`")
            st.markdown(f"**Processing Time:** `{result.get('processing_time_ms', 0):.2f} ms`")

        with col2:
            st.markdown(f"**Confidence Score:** `{result.get('confidence_score', 0):.2f}`")
            st.markdown(f"**Client ID:** `{result.get('client_id', 'N/A')}`")

def render_security_operations_center():
    """Render Security Operations Center - main dashboard page"""
    st.header("🏠 Security Operations Center")
    
    st.markdown("""
    Welcome to SentinelShield — your AI security command center. 
    Monitor threats in real-time, scan prompts, and manage your security posture.
    """)
    
    # System Status Cards
    st.subheader("📊 System Overview")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Scans Today", "1,247", delta="+89")
    with col2:
        st.metric("Threats Blocked", "23", delta="+3")
    with col3:
        st.metric("Active Agents", "3", delta="0")
    with col4:
        st.metric("System Health", "99.8%", delta="+0.2%")
    
    # Scan Activity Over Time
    st.subheader("📈 Scan Activity (Last 24 Hours)")
    
    if pd is not None and np is not None and go is not None:
        import random
        hours = pd.date_range(end=datetime.now(), periods=24, freq='h')
        scans = [random.randint(30, 80) for _ in range(24)]
        blocked = [random.randint(0, 5) for _ in range(24)]
        
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=hours, y=scans, mode='lines+markers',
            name='Scans', line=dict(color='#2E86AB', width=2)
        ))
        fig.add_trace(go.Bar(
            x=hours, y=blocked,
            name='Blocked', marker_color='#dc3545', opacity=0.6
        ))
        fig.update_layout(
            height=350,
            xaxis_title="Time",
            yaxis_title="Count",
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
            margin=dict(l=20, r=20, t=30, b=20)
        )
        st.plotly_chart(fig, use_container_width=True)
    
    # Recent Threat Activity
    st.subheader("🚨 Recent Threat Activity")
    
    recent_threats = [
        {"Time": "2 min ago", "Type": "Prompt Injection", "Risk": 0.92, "Decision": "BLOCK"},
        {"Time": "8 min ago", "Type": "Data Exfiltration", "Risk": 0.78, "Decision": "BLOCK"},
        {"Time": "15 min ago", "Type": "Jailbreak Attempt", "Risk": 0.65, "Decision": "REVIEW"},
        {"Time": "22 min ago", "Type": "Social Engineering", "Risk": 0.45, "Decision": "ALLOW"},
        {"Time": "30 min ago", "Type": "Safe Prompt", "Risk": 0.05, "Decision": "ALLOW"},
    ]
    
    if pd is not None:
        threat_df = pd.DataFrame(recent_threats)
        
        def color_decision(val):
            if val == "BLOCK":
                return 'background-color: #f8d7da; color: #721c24'
            elif val == "REVIEW":
                return 'background-color: #fff3cd; color: #856404'
            else:
                return 'background-color: #d4edda; color: #155724'
        
        styled = threat_df.style.applymap(color_decision, subset=['Decision'])
        st.dataframe(styled, use_container_width=True)
    
    # OWASP Coverage Quick View
    st.subheader("🛡️ OWASP LLM Top 10 Coverage")
    
    if go is not None:
        categories = ['LLM01', 'LLM02', 'LLM03', 'LLM04', 'LLM05', 
                      'LLM06', 'LLM07', 'LLM08', 'LLM09', 'LLM10']
        scores = [0.95, 0.92, 0.88, 0.90, 0.85, 0.91, 0.87, 0.93, 0.89, 0.86]
        
        fig = go.Figure(data=go.Scatterpolar(
            r=scores,
            theta=categories,
            fill='toself',
            fillcolor='rgba(46, 134, 171, 0.3)',
            line=dict(color='#2E86AB')
        ))
        fig.update_layout(
            polar=dict(radialaxis=dict(visible=True, range=[0, 1])),
            height=400,
            margin=dict(l=40, r=40, t=40, b=40)
        )
        st.plotly_chart(fig, use_container_width=True)


def render_red_team_lab():
    """Render Red Team Testing Lab"""
    st.header("🔴 Red Team Testing Lab")
    
    st.markdown("""
    Test your AI systems against real-world attack patterns. 
    Our red team engine simulates various attack vectors to identify vulnerabilities.
    """)
    
    # Target configuration
    st.subheader("🎯 Target Configuration")
    
    col1, col2 = st.columns(2)
    
    with col1:
        target_endpoint = st.text_input(
            "Target Endpoint",
            value="https://your-llm-api.com/chat",
            help="The API endpoint to test"
        )
        
        target_type = st.selectbox(
            "Target Type",
            ["openai_compatible", "azure_openai", "anthropic", "huggingface", "custom"]
        )
    
    with col2:
        intensity = st.selectbox(
            "Testing Intensity",
            ["quick", "standard", "comprehensive"],
            index=1,
            help="Number of attack payloads to test"
        )
        
        max_attacks = st.slider(
            "Maximum Attacks",
            min_value=50,
            max_value=500,
            value=200,
            step=50
        )
    
    # Attack categories
    st.subheader("⚔️ Attack Categories")
    
    categories = st.multiselect(
        "Select Attack Categories",
        [
            "prompt_injection",
            "jailbreak",
            "data_exfiltration",
            "model_theft",
            "social_engineering",
            "privilege_escalation",
            "goal_hijacking",
            "agent_compromise",
            "denial_of_service",
            "supply_chain"
        ],
        default=["prompt_injection", "jailbreak", "data_exfiltration"]
    )
    
    # Start test button
    if st.button("🚀 Start Red Team Test", type="primary"):
        if not target_endpoint:
            st.error("Please provide a target endpoint")
        elif not categories:
            st.error("Please select at least one attack category")
        else:
            with st.spinner("Initializing red team test..."):
                # Prepare request
                test_request = {
                    "target_endpoint": target_endpoint,
                    "target_type": target_type,
                    "categories": categories,
                    "intensity": intensity,
                    "max_attacks": max_attacks
                }
                
                # Start test (this would be an actual API call)
                result = dashboard.post_api_data("/redteam/start", test_request)
                
                if result:
                    st.success(f"Red team test started! Job ID: {result.get('job_id', 'unknown')}")
                    st.info(f"Estimated time: {result.get('estimated_time_seconds', 120)} seconds")
                    
                    # Store job ID for status checking
                    st.session_state.redteam_job_id = result.get('job_id')
                else:
                    st.error("Failed to start red team test")
    
    # Job status
    if 'redteam_job_id' in st.session_state:
        st.subheader("📊 Test Progress")
        
        job_id = st.session_state.redteam_job_id
        job_status = dashboard.get_api_data(f"/redteam/report/{job_id}")
        
        if job_status:
            # Progress bar
            progress = job_status.get('progress', 0)
            st.progress(progress / 100)
            
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.metric("Status", job_status.get('status', 'Unknown'))
            
            with col2:
                st.metric("Progress", f"{progress:.1f}%")
            
            with col3:
                attacks_run = job_status.get('attacks_run', 0)
                st.metric("Attacks Run", attacks_run)
            
            # Show results if completed
            if job_status.get('status') == 'completed':
                st.subheader("📋 Test Results")
                
                col1, col2 = st.columns(2)
                
                with col1:
                    st.metric("Security Score", f"{job_status.get('security_score', 0):.1f}")
                    st.metric("Grade", job_status.get('grade', 'N/A'))
                
                with col2:
                    st.metric("Attacks Blocked", job_status.get('attacks_blocked', 0))
                    st.metric("Success Rate", f"{job_status.get('attacks_succeeded', 0)}")
                
                # Vulnerabilities
                vulnerabilities = job_status.get('critical_vulnerabilities', [])
                if vulnerabilities:
                    st.subheader("🚨 Critical Vulnerabilities Found")
                    
                    for vuln in vulnerabilities:
                        st.error(f"**{vuln.get('category', 'Unknown')}**: {vuln.get('description', 'No description')}")
                        st.code(f"Payload: {vuln.get('payload', 'No payload')}")
                        st.info(f"Remediation: {vuln.get('remediation', 'No remediation advice')}")
                        st.markdown("---")
                
                # OWASP Coverage
                owasp_coverage = job_status.get('owasp_coverage', {})
                if owasp_coverage:
                    st.subheader("📚 OWASP LLM Top 10 Coverage")
                    
                    coverage_df = pd.DataFrame(
                        list(owasp_coverage.items()),
                        columns=['Category', 'Status']
                    )
                    
                    def color_status(val):
                        if val == 'PROTECTED':
                            return 'background-color: #d4edda'
                        elif val == 'VULNERABLE':
                            return 'background-color: #f8d7da'
                        else:
                            return 'background-color: #fff3cd'
                    
                    styled_coverage = coverage_df.style.applymap(color_status, subset=['Status'])
                    st.dataframe(styled_coverage, use_container_width=True)
        else:
            st.info("Click 'Refresh' to check job status")
            
            if st.button("Refresh"):
                st.rerun()

def render_agent_monitor():
    """Render Agent Security Monitor"""
    st.header("🤖 Agent Security Monitor")
    
    st.markdown("""
    Monitor AI agent behavior in real-time. Detect goal hijacking, 
    privilege escalation, and other security violations.
    """)
    
    # Active agents
    st.subheader("📊 Active Agents")
    
    # Sample agent data
    agents = [
        {
            "agent_id": "agent_001",
            "session_id": "sess_abc123",
            "role": "customer_service",
            "status": "ACTIVE",
            "risk_score": 0.2,
            "actions": 45,
            "blocked": 0,
            "goal": "Handle customer inquiries"
        },
        {
            "agent_id": "agent_002",
            "session_id": "sess_def456",
            "role": "data_analyst",
            "status": "ACTIVE",
            "risk_score": 0.6,
            "actions": 120,
            "blocked": 3,
            "goal": "Analyze sales data"
        },
        {
            "agent_id": "agent_003",
            "session_id": "sess_ghi789",
            "role": "content_creator",
            "status": "QUARANTINED",
            "risk_score": 0.9,
            "actions": 25,
            "blocked": 8,
            "goal": "Generate marketing content"
        }
    ]
    
    agent_df = pd.DataFrame(agents)
    
    def color_status(val):
        if val == "ACTIVE":
            return 'background-color: #d4edda'
        elif val == "QUARANTINED":
            return 'background-color: #f8d7da'
        else:
            return 'background-color: #fff3cd'
    
    def color_risk(val):
        if val >= 0.8:
            return 'background-color: #f8d7da'
        elif val >= 0.6:
            return 'background-color: #fff3cd'
        else:
            return 'background-color: #d4edda'
    
    styled_agents = agent_df.style.applymap(color_status, subset=['status'])
    styled_agents = styled_agents.applymap(color_risk, subset=['risk_score'])
    
    st.dataframe(styled_agents, use_container_width=True)
    
    # Risk distribution
    st.subheader("📈 Risk Distribution")
    
    fig = go.Figure(data=[
        go.Bar(name='Low Risk', x=['Risk Levels'], y=[1], marker_color='#28a745'),
        go.Bar(name='Medium Risk', x=['Risk Levels'], y=[1], marker_color='#ffc107'),
        go.Bar(name='High Risk', x=['Risk Levels'], y=[1], marker_color='#fd7e14'),
        go.Bar(name='Critical Risk', x=['Risk Levels'], y=[1], marker_color='#dc3545')
    ])
    
    fig.update_layout(
        title="Agent Risk Distribution",
        barmode='stack',
        height=400
    )
    
    st.plotly_chart(fig, use_container_width=True)
    
    # Recent actions
    st.subheader("⚡ Recent Agent Actions")
    
    # Sample action data
    actions = [
        {
            "timestamp": "2026-02-17 14:30:00",
            "agent_id": "agent_002",
            "action": "database_query",
            "tool": "sql_analyzer",
            "risk_score": 0.7,
            "blocked": True,
            "reason": "Unauthorized data access"
        },
        {
            "timestamp": "2026-02-17 14:28:00",
            "agent_id": "agent_003",
            "action": "file_access",
            "tool": "file_reader",
            "risk_score": 0.9,
            "blocked": True,
            "reason": "Attempted system file access"
        },
        {
            "timestamp": "2026-02-17 14:25:00",
            "agent_id": "agent_001",
            "action": "customer_lookup",
            "tool": "crm_system",
            "risk_score": 0.1,
            "blocked": False,
            "reason": ""
        }
    ]
    
    action_df = pd.DataFrame(actions)
    
    def color_action_risk(val):
        if val >= 0.8:
            return 'background-color: #f8d7da'
        elif val >= 0.6:
            return 'background-color: #fff3cd'
        else:
            return 'background-color: #d4edda'
    
    styled_actions = action_df.style.applymap(color_action_risk, subset=['risk_score'])
    st.dataframe(styled_actions, use_container_width=True)
    
    # Kill switch status
    st.subheader("🛑 Kill Switch Status")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("Active Kill Switches", "2")
    
    with col2:
        st.metric("Total Terminations", "5")
    
    with col3:
        st.metric("Success Rate", "100%")
    
    # Emergency controls
    st.subheader("🚨 Emergency Controls")
    
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("🛑 Emergency Stop All Agents", type="secondary"):
            st.warning("Emergency stop would terminate all active agents")
    
    with col2:
        if st.button("🔒 Lock Down System", type="secondary"):
            st.warning("Lock down would prevent new agent registrations")

def render_compliance_dashboard():
    """Render Compliance Dashboard"""
    st.header("📊 Compliance Dashboard")
    
    st.markdown("""
    Monitor OWASP LLM Top 10 compliance and generate regulatory reports.
    Track your security posture against industry standards.
    """)
    
    # Overall compliance score
    st.subheader("📈 Overall Compliance Score")
    
    # Sample compliance data
    overall_score = 0.78
    grade = "B+"
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        # Gauge chart for overall score
        fig = go.Figure(go.Indicator(
            mode = "gauge+number+delta",
            value = overall_score,
            domain = {'x': [0, 1], 'y': [0, 1]},
            title = {'text': "Compliance Score"},
            gauge = {
                'axis': {'range': [None, 1]},
                'bar': {'color': "darkblue"},
                'steps': [
                    {'range': [0, 0.5], 'color': "lightgray"},
                    {'range': [0.5, 0.7], 'color': "yellow"},
                    {'range': [0.7, 0.9], 'color': "lightgreen"},
                    {'range': [0.9, 1], 'color': "green"}
                ],
                'threshold': {
                    'line': {'color': "red", 'width': 4},
                    'thickness': 0.75,
                    'value': 0.9
                }
            }
        ))
        
        fig.update_layout(height=300)
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.metric("Grade", grade)
        st.metric("Compliant Categories", "7/10")
        st.metric("Last Assessment", "2026-02-17")
    
    with col3:
        # Compliance trend
        dates = pd.date_range(start='2026-02-01', end='2026-02-17', freq='D')
        scores = np.random.uniform(0.7, 0.85, len(dates))
        
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=dates,
            y=scores,
            mode='lines',
            name='Compliance Score',
            line=dict(color='#2E86AB')
        ))
        
        fig.update_layout(
            title="Compliance Trend",
            xaxis_title="Date",
            yaxis_title="Score",
            height=300,
            showlegend=False
        )
        
        st.plotly_chart(fig, use_container_width=True)
    
    # OWASP Top 10 breakdown
    st.subheader("🛡️ OWASP LLM Top 10 Coverage")
    
    owasp_data = {
        'Category': ['LLM01', 'LLM02', 'LLM03', 'LLM04', 'LLM05', 'LLM06', 'LLM07', 'LLM08', 'LLM09', 'LLM10'],
        'Status': ['PROTECTED', 'PROTECTED', 'VULNERABLE', 'PROTECTED', 'PARTIAL', 'PROTECTED', 'VULNERABLE', 'PROTECTED', 'PROTECTED', 'PARTIAL'],
        'Score': [0.95, 0.92, 0.45, 0.88, 0.65, 0.91, 0.38, 0.85, 0.90, 0.62]
    }
    
    owasp_df = pd.DataFrame(owasp_data)
    
    def color_owasp_status(val):
        if val == 'PROTECTED':
            return 'background-color: #d4edda'
        elif val == 'PARTIAL':
            return 'background-color: #fff3cd'
        else:
            return 'background-color: #f8d7da'
    
    styled_owasp = owasp_df.style.applymap(color_owasp_status, subset=['Status'])
    st.dataframe(styled_owasp, use_container_width=True)
    
    # Bar chart for scores
    fig = px.bar(
        owasp_df,
        x='Category',
        y='Score',
        color='Status',
        title="OWASP LLM Top 10 Scores",
        color_discrete_map={
            'PROTECTED': '#28a745',
            'PARTIAL': '#ffc107',
            'VULNERABLE': '#dc3545'
        }
    )
    
    st.plotly_chart(fig, use_container_width=True)
    
    # Generate report button
    st.subheader("📄 Generate Compliance Report")
    
    col1, col2 = st.columns(2)
    
    with col1:
        report_type = st.selectbox(
            "Report Type",
            ["OWASP LLM Top 10", "GDPR Assessment", "SOC2 Report", "Custom Report"]
        )
        
        period = st.selectbox(
            "Reporting Period",
            ["Last 30 Days", "Last Quarter", "Last Year", "Custom Range"]
        )
    
    with col2:
        format_type = st.selectbox(
            "Format",
            ["PDF", "JSON", "CSV"]
        )
        
        if st.button("📊 Generate Report", type="primary"):
            st.success(f"Generating {report_type} report for {period} in {format_type} format...")
            # In real implementation, would call API to generate report
    
    # Recent reports
    st.subheader("📋 Recent Compliance Reports")
    
    reports = [
        {
            "report_id": "owasp_20260217",
            "type": "OWASP LLM Top 10",
            "generated": "2026-02-17 10:00:00",
            "score": 0.78,
            "grade": "B+",
            "status": "Completed"
        },
        {
            "report_id": "gdpr_20260215",
            "type": "GDPR Assessment",
            "generated": "2026-02-15 14:30:00",
            "score": 0.85,
            "grade": "A-",
            "status": "Completed"
        },
        {
            "report_id": "soc2_20260210",
            "type": "SOC2 Report",
            "generated": "2026-02-10 09:15:00",
            "score": 0.72,
            "grade": "B",
            "status": "Completed"
        }
    ]
    
    report_df = pd.DataFrame(reports)
    st.dataframe(report_df, use_container_width=True)

def render_threat_intelligence():
    """Render Threat Intelligence"""
    st.header("🧠 Threat Intelligence")
    
    st.markdown("""
    Advanced threat analysis and intelligence. Monitor emerging attack patterns,
    threat actor activities, and vulnerability trends.
    """)
    
    # Attack trends
    st.subheader("📈 Attack Trends (30 Days)")
    
    # Sample trend data
    dates = pd.date_range(start='2026-01-18', end='2026-02-17', freq='D')
    
    # Generate realistic trend data
    base_trend = np.sin(np.linspace(0, 2*np.pi, len(dates))) * 10 + 20
    noise = np.random.normal(0, 2, len(dates))
    attack_trend = np.maximum(0, base_trend + noise)
    
    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=dates,
        y=attack_trend,
        mode='lines',
        name='Daily Attacks',
        line=dict(color='#FF6B6B')
    ))
    
    # Add 7-day moving average
    moving_avg = pd.Series(attack_trend).rolling(window=7).mean()
    fig.add_trace(go.Scatter(
        x=dates,
        y=moving_avg,
        mode='lines',
        name='7-Day Average',
        line=dict(color='#4ECDC4')
    ))
    
    fig.update_layout(
        title="Attack Volume Trend",
        xaxis_title="Date",
        yaxis_title="Number of Attacks",
        height=400
    )
    
    st.plotly_chart(fig, use_container_width=True)
    
    # Top attack vectors
    st.subheader("🎯 Top Attack Vectors")
    
    attack_vectors = {
        'Prompt Injection': 156,
        'Jailbreak': 98,
        'Data Exfiltration': 87,
        'Social Engineering': 65,
        'Model Theft': 43,
        'Privilege Escalation': 32,
        'Goal Hijacking': 28,
        'Denial of Service': 15,
        'Supply Chain': 12,
        'Other': 8
    }
    
    fig = px.bar(
        x=list(attack_vectors.keys()),
        y=list(attack_vectors.values()),
        title="Attack Vector Distribution (30 Days)",
        labels={'x': 'Attack Type', 'y': 'Count'}
    )
    
    fig.update_xaxis(tickangle=45)
    st.plotly_chart(fig, use_container_width=True)
    
    # Geographic distribution
    st.subheader("🌍 Geographic Distribution")
    
    # Sample geo data
    geo_data = {
        'Country': ['United States', 'China', 'Russia', 'Germany', 'United Kingdom', 'France', 'India', 'Brazil'],
        'Attacks': [245, 189, 167, 134, 98, 87, 76, 65]
    }
    
    geo_df = pd.DataFrame(geo_data)
    
    fig = px.choropleth(
        geo_df,
        locations="Country",
        locationmode="country names",
        color="Attacks",
        hover_name="Country",
        hover_data=["Attacks"],
        color_continuous_scale="Reds",
        title="Attack Origins by Country"
    )
    
    st.plotly_chart(fig, use_container_width=True)
    
    # Emerging threats
    st.subheader("🚨 Emerging Threats")
    
    emerging_threats = [
        {
            "threat": "Multi-modal Prompt Injection",
            "description": "Attacks combining text, image, and audio inputs",
            "severity": "HIGH",
            "first_seen": "2026-02-15",
            "confidence": 0.85
        },
        {
            "threat": "Agent Chain Compromise",
            "description": "Coordinated attacks across multiple AI agents",
            "severity": "CRITICAL",
            "first_seen": "2026-02-12",
            "confidence": 0.92
        },
        {
            "threat": "Contextual Data Poisoning",
            "description": "Subtle training data manipulation over time",
            "severity": "MEDIUM",
            "first_seen": "2026-02-10",
            "confidence": 0.78
        }
    ]
    
    for threat in emerging_threats:
        severity_color = {
            'CRITICAL': '#dc3545',
            'HIGH': '#fd7e14',
            'MEDIUM': '#ffc107',
            'LOW': '#28a745'
        }.get(threat['severity'], '#6c757d')
        
        st.markdown(f"""
        <div style="border-left: 4px solid {severity_color}; padding-left: 1rem; margin: 1rem 0;">
            <h4>{threat['threat']}</h4>
            <p><strong>Description:</strong> {threat['description']}</p>
            <p><strong>Severity:</strong> <span style="color: {severity_color}; font-weight: bold;">{threat['severity']}</span></p>
            <p><strong>First Seen:</strong> {threat['first_seen']}</p>
            <p><strong>Confidence:</strong> {threat['confidence']:.2f}</p>
        </div>
        """, unsafe_allow_html=True)

def render_settings():
    """Render Settings page"""
    st.header("⚙️ Settings")
    
    # API Configuration
    st.subheader("🔌 API Configuration")
    
    col1, col2 = st.columns(2)
    
    with col1:
        api_url = st.text_input(
            "API Base URL",
            value="http://localhost:8000/api/v1",
            help="Base URL for SentinelShield API"
        )
        
        api_key = st.text_input(
            "API Key",
            type="password",
            help="Your API authentication key"
        )
    
    with col2:
        timeout = st.slider(
            "Request Timeout (seconds)",
            min_value=5,
            max_value=60,
            value=30
        )
        
        retry_attempts = st.slider(
            "Retry Attempts",
            min_value=0,
            max_value=5,
            value=3
        )
    
    # Display Settings
    st.subheader("🎨 Display Settings")
    
    refresh_interval = st.slider(
        "Auto Refresh Interval (seconds)",
        min_value=5,
        max_value=300,
        value=30,
        help="How often to refresh dashboard data"
    )
    
    theme = st.selectbox(
        "Theme",
        ["Light", "Dark", "Auto"],
        index=2
    )
    
    # Notification Settings
    st.subheader("🔔 Notification Settings")
    
    email_alerts = st.checkbox("Email Alerts", value=True)
    slack_alerts = st.checkbox("Slack Alerts", value=True)
    
    if email_alerts:
        email_address = st.text_input("Email Address")
    
    if slack_alerts:
        slack_webhook = st.text_input("Slack Webhook URL")
    
    # Save settings
    if st.button("💾 Save Settings", type="primary"):
        st.success("Settings saved successfully!")
    
    # System Information
    st.subheader("ℹ️ System Information")
    
    system_info = {
        "Platform": "SentinelShield AI Security Platform",
        "Version": "1.0.0",
        "Python Version": "3.9+",
        "Streamlit Version": "1.28.0",
        "Last Updated": "2026-02-17"
    }
    
    for key, value in system_info.items():
        st.write(f"**{key}:** {value}")

# Render selected page
if page == "🏠 Security Operations Center":
    render_security_operations_center()
elif page == "🔴 Red Team Testing Lab":
    render_red_team_lab()
elif page == "🤖 Agent Security Monitor":
    render_agent_monitor()
elif page == "📊 Compliance Dashboard":
    render_compliance_dashboard()
elif page == "🧠 Threat Intelligence":
    render_threat_intelligence()
elif page == "⚙️ Settings":
    render_settings()

# Auto-refresh functionality
if 'auto_refresh' not in st.session_state:
    st.session_state.auto_refresh = True

auto_refresh = st.sidebar.checkbox("Auto Refresh", value=st.session_state.auto_refresh)
st.session_state.auto_refresh = auto_refresh

if auto_refresh:
    time.sleep(30)  # Refresh every 30 seconds
    st.rerun()

# Footer
st.markdown("---")
st.markdown(
    """
    <div style='text-align: center; color: #666; font-size: 0.8em;'>
        SentinelShield AI Security Platform v1.0.0 | Built for Production-Grade AI Security
    </div>
    """, unsafe_allow_html=True)
