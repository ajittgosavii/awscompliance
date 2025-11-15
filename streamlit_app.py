import streamlit as st
import pandas as pd
import time
import random
from datetime import datetime, timedelta

# Page configuration
st.set_page_config(
    page_title="Multi-Account Compliance Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(to right, #2563eb, #9333ea, #2563eb);
        color: white;
        padding: 2rem;
        border-radius: 10px;
        margin-bottom: 2rem;
    }
    .metric-card {
        background: white;
        border: 1px solid #e5e7eb;
        border-radius: 8px;
        padding: 1.5rem;
        margin: 0.5rem 0;
    }
    .status-badge {
        padding: 0.25rem 0.75rem;
        border-radius: 12px;
        font-size: 0.75rem;
        font-weight: 600;
    }
    .critical { background: #fee2e2; color: #991b1b; }
    .high { background: #fed7aa; color: #9a3412; }
    .medium { background: #fef3c7; color: #92400e; }
    .low { background: #dbeafe; color: #1e40af; }
    .active { background: #d1fae5; color: #065f46; }
    .stProgress > div > div > div > div {
        background-color: #3b82f6;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'active_view' not in st.session_state:
    st.session_state.active_view = 'dashboard'
if 'simulation_running' not in st.session_state:
    st.session_state.simulation_running = False
if 'e2e_running' not in st.session_state:
    st.session_state.e2e_running = False
if 'e2e_stage' not in st.session_state:
    st.session_state.e2e_stage = 0
if 'findings' not in st.session_state:
    st.session_state.findings = []
if 'remediation_logs' not in st.session_state:
    st.session_state.remediation_logs = []

# Architecture layers data
ARCHITECTURE_LAYERS = {
    'aggregation': {
        'name': 'Aggregation Layer',
        'color': '#3b82f6',
        'description': 'Centralized security data collection from all 950 member accounts',
        'services': [
            {'name': 'Central Security Hub', 'status': 'Active', 'findings': 247, 'enabled': 950},
            {'name': 'AWS Config Aggregator', 'status': 'Active', 'findings': 0, 'rules': 145},
            {'name': 'CloudTrail Organization Trail', 'status': 'Active', 'events': 1234567},
            {'name': 'GuardDuty Master Account', 'status': 'Active', 'findings': 34, 'threats': 34},
            {'name': 'EventBridge', 'status': 'Active', 'eventsProcessed': 456789},
            {'name': 'SNS Topics', 'status': 'Active', 'topics': 12}
        ]
    },
    'intelligence': {
        'name': 'Intelligence Layer',
        'color': '#eab308',
        'description': 'AI-powered analysis and recommendations using AWS Bedrock',
        'services': [
            {'name': 'AWS Bedrock (Claude AI)', 'status': 'Active', 'analysisCompleted': 3456},
            {'name': 'Knowledge Bases', 'status': 'Active', 'documents': 1234},
            {'name': 'CVE & Vulnerability Analysis', 'status': 'Active', 'cvesAssessed': 1234},
            {'name': 'AI Recommendations Engine', 'status': 'Active', 'generated': 892},
            {'name': 'Contextual Processing', 'status': 'Active', 'contexts': 23}
        ]
    },
    'visualization': {
        'name': 'Visualization Layer',
        'color': '#22c55e',
        'description': 'Executive dashboards and compliance reporting',
        'services': [
            {'name': 'Amazon QuickSight', 'status': 'Active', 'dashboards': 34, 'users': 156},
            {'name': 'Compliance Dashboards', 'status': 'Active', 'frameworks': 4, 'compliance': '92.4%'},
            {'name': 'Athena Query Engine', 'status': 'Active', 'queries': 2345},
            {'name': 'S3 Data Lake', 'status': 'Active', 'size': '234TB'},
            {'name': 'Automated Reports', 'status': 'Active', 'scheduled': 23},
            {'name': 'Alert Management', 'status': 'Active', 'rules': 67}
        ]
    },
    'orchestration': {
        'name': 'Orchestration Layer',
        'color': '#a855f7',
        'description': 'Automated remediation and workflow orchestration',
        'services': [
            {'name': 'Step Functions', 'status': 'Active', 'workflows': 45},
            {'name': 'Lambda Functions', 'status': 'Active', 'functions': 123},
            {'name': 'SSM Automation', 'status': 'Active', 'runbooks': 78},
            {'name': 'Approval Workflows', 'status': 'Active', 'pending': 12},
            {'name': 'Change Management', 'status': 'Active', 'changes': 234}
        ]
    }
}

# Sample findings data
SAMPLE_FINDINGS = [
    {
        'id': 'F001',
        'title': 'S3 Bucket Publicly Accessible',
        'severity': 'Critical',
        'account': 'prod-account-123',
        'resource': 's3://data-bucket-prod',
        'framework': 'PCI DSS 3.2.1',
        'control': '1.2.1',
        'description': 'S3 bucket allows public read access',
        'recommendation': 'Remove public access and enable bucket encryption',
        'status': 'Open'
    },
    {
        'id': 'F002',
        'title': 'IAM User Without MFA',
        'severity': 'High',
        'account': 'dev-account-456',
        'resource': 'iam-user/john.doe',
        'framework': 'SOC 2',
        'control': 'CC6.1',
        'description': 'IAM user has console access without MFA enabled',
        'recommendation': 'Enable MFA for all users with console access',
        'status': 'In Progress'
    },
    {
        'id': 'F003',
        'title': 'Unencrypted EBS Volume',
        'severity': 'High',
        'account': 'prod-account-789',
        'resource': 'vol-0abc123def456',
        'framework': 'HIPAA',
        'control': '164.312(a)(2)(iv)',
        'description': 'EBS volume is not encrypted at rest',
        'recommendation': 'Create encrypted snapshot and replace volume',
        'status': 'Open'
    },
    {
        'id': 'F004',
        'title': 'Security Group Allows 0.0.0.0/0',
        'severity': 'Medium',
        'account': 'staging-account-321',
        'resource': 'sg-0123456789abcdef',
        'framework': 'GDPR',
        'control': 'Article 32',
        'description': 'Security group allows unrestricted inbound access',
        'recommendation': 'Restrict access to specific IP ranges',
        'status': 'Open'
    },
    {
        'id': 'F005',
        'title': 'RDS Instance Not in VPC',
        'severity': 'Critical',
        'account': 'prod-account-123',
        'resource': 'rds-instance-legacy',
        'framework': 'PCI DSS 3.2.1',
        'control': '1.3.4',
        'description': 'RDS instance is not deployed in a VPC',
        'recommendation': 'Migrate RDS instance to VPC',
        'status': 'Open'
    },
    {
        'id': 'F006',
        'title': 'CloudTrail Logging Disabled',
        'severity': 'High',
        'account': 'test-account-654',
        'resource': 'us-west-2',
        'framework': 'SOC 2',
        'control': 'CC7.2',
        'description': 'CloudTrail logging is not enabled in this region',
        'recommendation': 'Enable CloudTrail logging for all regions',
        'status': 'Open'
    },
    {
        'id': 'F007',
        'title': 'Lambda Function Without Dead Letter Queue',
        'severity': 'Medium',
        'account': 'dev-account-456',
        'resource': 'lambda-function-processor',
        'framework': 'Best Practice',
        'control': 'N/A',
        'description': 'Lambda function does not have a dead letter queue configured',
        'recommendation': 'Configure DLQ for failed invocations',
        'status': 'Open'
    },
    {
        'id': 'F008',
        'title': 'EC2 Instance Missing Security Patches',
        'severity': 'High',
        'account': 'prod-account-789',
        'resource': 'i-0987654321fedcba',
        'framework': 'HIPAA',
        'control': '164.308(a)(5)(ii)(B)',
        'description': '23 critical security patches missing on EC2 instance',
        'recommendation': 'Apply security patches using SSM Patch Manager',
        'status': 'In Progress'
    }
]

# Compliance metrics
COMPLIANCE_METRICS = {
    'PCI DSS': {'score': 94, 'controls_passed': 235, 'controls_total': 250},
    'HIPAA': {'score': 91, 'controls_passed': 182, 'controls_total': 200},
    'GDPR': {'score': 96, 'controls_passed': 144, 'controls_total': 150},
    'SOC 2': {'score': 93, 'controls_passed': 186, 'controls_total': 200}
}

def render_header():
    """Render the main header"""
    st.markdown("""
    <div class="main-header">
        <div style="display: flex; justify-content: space-between; align-items: center;">
            <div>
                <h1 style="margin: 0; font-size: 2rem;">🛡️ Multi-Account Compliance Platform</h1>
                <p style="margin: 0.5rem 0 0 0; opacity: 0.9;">
                    Centralized Intelligence, Visualization & Automated Remediation across 950 AWS Accounts
                </p>
            </div>
            <div style="text-align: right; background: rgba(255,255,255,0.2); padding: 1rem; border-radius: 8px;">
                <p style="margin: 0; font-size: 0.875rem; opacity: 0.9;">Central Management Account</p>
                <p style="margin: 0; font-size: 2rem; font-weight: bold;">950 Accounts</p>
                <p style="margin: 0; font-size: 0.75rem; opacity: 0.8;">Real-time monitoring</p>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

def render_dashboard():
    """Render the main dashboard view"""
    st.markdown("## 📊 Compliance Dashboard")
    
    # Compliance Framework Metrics
    st.markdown("### Compliance Framework Status")
    cols = st.columns(4)
    for idx, (framework, data) in enumerate(COMPLIANCE_METRICS.items()):
        with cols[idx]:
            st.metric(
                label=framework,
                value=f"{data['score']}%",
                delta=f"{data['controls_passed']}/{data['controls_total']} controls"
            )
            st.progress(data['score'] / 100)
    
    st.markdown("---")
    
    # Architecture Layers Overview
    st.markdown("### 🏗️ Platform Architecture Layers")
    
    for layer_id, layer in ARCHITECTURE_LAYERS.items():
        with st.expander(f"{layer['name']} - {len(layer['services'])} Services", expanded=False):
            st.markdown(f"**Description:** {layer['description']}")
            
            # Create a dataframe for services
            services_data = []
            for service in layer['services']:
                services_data.append({
                    'Service': service['name'],
                    'Status': service['status'],
                    'Key Metric': list(service.items())[2] if len(service.items()) > 2 else ('', '')
                })
            
            df = pd.DataFrame(services_data)
            st.dataframe(df, use_container_width=True, hide_index=True)
    
    st.markdown("---")
    
    # Key Platform Metrics
    st.markdown("### 📈 Platform Performance Metrics")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown("""
        <div class="metric-card">
            <h4 style="margin-top: 0;">Total Findings</h4>
            <h2 style="color: #ef4444; margin: 0.5rem 0;">247</h2>
            <p style="margin: 0; font-size: 0.875rem; color: #6b7280;">18 Critical, 67 High</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown("""
        <div class="metric-card">
            <h4 style="margin-top: 0;">Accounts Monitored</h4>
            <h2 style="color: #3b82f6; margin: 0.5rem 0;">950</h2>
            <p style="margin: 0; font-size: 0.875rem; color: #6b7280;">100% Coverage</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown("""
        <div class="metric-card">
            <h4 style="margin-top: 0;">Auto-Remediated</h4>
            <h2 style="color: #22c55e; margin: 0.5rem 0;">567</h2>
            <p style="margin: 0; font-size: 0.875rem; color: #6b7280;">This month</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col4:
        st.markdown("""
        <div class="metric-card">
            <h4 style="margin-top: 0;">AI Recommendations</h4>
            <h2 style="color: #eab308; margin: 0.5rem 0;">892</h2>
            <p style="margin: 0; font-size: 0.875rem; color: #6b7280;">94% Accuracy</p>
        </div>
        """, unsafe_allow_html=True)
    
    st.markdown("---")
    
    # Recent Activity
    st.markdown("### 🔔 Recent Activity")
    activity_data = [
        {'Time': '2 mins ago', 'Event': 'Critical finding remediated in prod-account-123', 'Type': '✅ Remediation'},
        {'Time': '15 mins ago', 'Event': 'New security finding detected: S3 bucket exposure', 'Type': '⚠️ Alert'},
        {'Time': '1 hour ago', 'Event': 'Compliance scan completed across 950 accounts', 'Type': '🔍 Scan'},
        {'Time': '2 hours ago', 'Event': 'AI recommendation accepted and deployed', 'Type': '🤖 AI Action'},
        {'Time': '3 hours ago', 'Event': 'Monthly compliance report generated', 'Type': '📄 Report'}
    ]
    
    df_activity = pd.DataFrame(activity_data)
    st.dataframe(df_activity, use_container_width=True, hide_index=True)

def render_e2e_workflow():
    """Render the End-to-End Workflow view"""
    st.markdown("## 🔄 End-to-End Workflow Simulation")
    
    st.markdown("""
    This simulation demonstrates the complete automated workflow from security finding detection 
    to AI-powered analysis and automated remediation across the 950-account infrastructure.
    """)
    
    st.markdown("---")
    
    # Workflow stages
    stages = [
        {"name": "1. Detection", "description": "Security Hub aggregates finding from GuardDuty"},
        {"name": "2. EventBridge Trigger", "description": "Event detected and routed to processing"},
        {"name": "3. AI Analysis", "description": "Bedrock Claude analyzes severity and context"},
        {"name": "4. Recommendation", "description": "AI generates remediation recommendation"},
        {"name": "5. Approval Check", "description": "Determine if auto-remediation is approved"},
        {"name": "6. Orchestration", "description": "Step Functions triggers remediation workflow"},
        {"name": "7. Remediation", "description": "Lambda executes fix across accounts"},
        {"name": "8. Verification", "description": "Config verifies compliance restored"},
        {"name": "9. Notification", "description": "SNS notifies stakeholders of completion"},
        {"name": "10. Documentation", "description": "Audit trail stored in S3 Data Lake"}
    ]
    
    # Control buttons
    col1, col2, col3 = st.columns([1, 1, 4])
    
    with col1:
        if st.button("▶️ Start Simulation", disabled=st.session_state.e2e_running, use_container_width=True):
            st.session_state.e2e_running = True
            st.session_state.e2e_stage = 0
            st.rerun()
    
    with col2:
        if st.button("⏹️ Reset", use_container_width=True):
            st.session_state.e2e_running = False
            st.session_state.e2e_stage = 0
            st.rerun()
    
    st.markdown("---")
    
    # Display workflow stages
    if st.session_state.e2e_running and st.session_state.e2e_stage < len(stages):
        # Progress bar
        progress = (st.session_state.e2e_stage + 1) / len(stages)
        st.progress(progress, text=f"Progress: {int(progress * 100)}% - Stage {st.session_state.e2e_stage + 1} of {len(stages)}")
        
        # Current stage
        current_stage = stages[st.session_state.e2e_stage]
        st.markdown(f"""
        <div style="background: #dbeafe; border-left: 4px solid #3b82f6; padding: 1rem; margin: 1rem 0;">
            <h3 style="margin-top: 0; color: #1e40af;">⚡ {current_stage['name']}</h3>
            <p style="margin: 0;">{current_stage['description']}</p>
        </div>
        """, unsafe_allow_html=True)
        
        # Manual advance button
        if st.button("▶️ Next Stage", key="next_stage"):
            st.session_state.e2e_stage += 1
            st.rerun()
    
    elif st.session_state.e2e_stage >= len(stages):
        st.success("✅ **Workflow Completed Successfully!**")
        st.balloons()
        st.session_state.e2e_running = False
    
    # Display all stages
    st.markdown("### Workflow Stages")
    for idx, stage in enumerate(stages):
        if idx < st.session_state.e2e_stage:
            icon = "✅"
            style = "background: #d1fae5; border-left: 4px solid #10b981;"
        elif idx == st.session_state.e2e_stage:
            icon = "⏳"
            style = "background: #fef3c7; border-left: 4px solid #eab308;"
        else:
            icon = "⏺️"
            style = "background: #f3f4f6; border-left: 4px solid #9ca3af;"
        
        st.markdown(f"""
        <div style="{style} padding: 0.75rem; margin: 0.5rem 0;">
            <strong>{icon} {stage['name']}</strong>: {stage['description']}
        </div>
        """, unsafe_allow_html=True)
    
    st.markdown("---")
    
    # Integration Architecture
    st.markdown("### 🏗️ Integration Architecture")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown("""
        <div style="background: #1f2937; color: white; padding: 1rem; border-radius: 8px;">
            <h4 style="margin-top: 0;">💻 External Services</h4>
            <div style="background: #374151; padding: 0.5rem; margin: 0.5rem 0; border-radius: 4px; font-size: 0.875rem;">
                <strong>GitHub Repository</strong><br/>
                <span style="color: #d1d5db;">Policy as Code (IaC)</span>
            </div>
            <div style="background: #374151; padding: 0.5rem; margin: 0.5rem 0; border-radius: 4px; font-size: 0.875rem;">
                <strong>CI/CD Pipeline</strong><br/>
                <span style="color: #d1d5db;">GitHub Actions</span>
            </div>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown("""
        <div style="background: #ecfdf5; border: 1px solid #a7f3d0; padding: 1rem; border-radius: 8px;">
            <h4 style="margin-top: 0; color: #065f46;">☁️ Deployment</h4>
            <div style="background: white; border: 1px solid #a7f3d0; padding: 0.5rem; margin: 0.5rem 0; border-radius: 4px; font-size: 0.875rem;">
                <strong style="color: #065f46;">CloudFormation</strong><br/>
                <span style="color: #047857;">StackSets</span>
            </div>
            <div style="background: white; border: 1px solid #a7f3d0; padding: 0.5rem; margin: 0.5rem 0; border-radius: 4px; font-size: 0.875rem;">
                <strong style="color: #065f46;">950 Accounts</strong><br/>
                <span style="color: #047857;">Multi-Region</span>
            </div>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown("""
        <div style="background: #fef3c7; border: 1px solid #fde68a; padding: 1rem; border-radius: 8px;">
            <h4 style="margin-top: 0; color: #78350f;">🛡️ Detection & AI</h4>
            <div style="background: white; border: 1px solid #fde68a; padding: 0.5rem; margin: 0.5rem 0; border-radius: 4px; font-size: 0.875rem;">
                <strong style="color: #78350f;">Security Hub</strong><br/>
                <span style="color: #92400e;">Config, GuardDuty</span>
            </div>
            <div style="background: white; border: 1px solid #fde68a; padding: 0.5rem; margin: 0.5rem 0; border-radius: 4px; font-size: 0.875rem;">
                <strong style="color: #78350f;">AWS Bedrock</strong><br/>
                <span style="color: #92400e;">Claude AI</span>
            </div>
        </div>
        """, unsafe_allow_html=True)
    
    with col4:
        st.markdown("""
        <div style="background: #fae8ff; border: 1px solid #e9d5ff; padding: 1rem; border-radius: 8px;">
            <h4 style="margin-top: 0; color: #581c87;">⚡ Remediation</h4>
            <div style="background: white; border: 1px solid #e9d5ff; padding: 0.5rem; margin: 0.5rem 0; border-radius: 4px; font-size: 0.875rem;">
                <strong style="color: #581c87;">Step Functions</strong><br/>
                <span style="color: #6b21a8;">Orchestration</span>
            </div>
            <div style="background: white; border: 1px solid #e9d5ff; padding: 0.5rem; margin: 0.5rem 0; border-radius: 4px; font-size: 0.875rem;">
                <strong style="color: #581c87;">Lambda</strong><br/>
                <span style="color: #6b21a8;">Automated Fixes</span>
            </div>
        </div>
        """, unsafe_allow_html=True)

def render_findings():
    """Render the Security Findings view"""
    st.markdown("## 🔍 Security Findings")
    
    # Filters
    col1, col2, col3 = st.columns(3)
    
    with col1:
        severity_filter = st.multiselect(
            "Filter by Severity",
            options=['Critical', 'High', 'Medium', 'Low'],
            default=['Critical', 'High', 'Medium', 'Low']
        )
    
    with col2:
        framework_filter = st.multiselect(
            "Filter by Framework",
            options=['PCI DSS 3.2.1', 'SOC 2', 'HIPAA', 'GDPR', 'Best Practice'],
            default=['PCI DSS 3.2.1', 'SOC 2', 'HIPAA', 'GDPR', 'Best Practice']
        )
    
    with col3:
        status_filter = st.multiselect(
            "Filter by Status",
            options=['Open', 'In Progress', 'Resolved'],
            default=['Open', 'In Progress']
        )
    
    st.markdown("---")
    
    # Filter findings
    filtered_findings = [
        f for f in SAMPLE_FINDINGS
        if f['severity'] in severity_filter
        and f['framework'] in framework_filter
        and f['status'] in status_filter
    ]
    
    # Summary metrics
    col1, col2, col3, col4 = st.columns(4)
    
    critical_count = len([f for f in filtered_findings if f['severity'] == 'Critical'])
    high_count = len([f for f in filtered_findings if f['severity'] == 'High'])
    medium_count = len([f for f in filtered_findings if f['severity'] == 'Medium'])
    low_count = len([f for f in filtered_findings if f['severity'] == 'Low'])
    
    col1.metric("Critical", critical_count, delta=None)
    col2.metric("High", high_count, delta=None)
    col3.metric("Medium", medium_count, delta=None)
    col4.metric("Low", low_count, delta=None)
    
    st.markdown("---")
    
    # Display findings
    for finding in filtered_findings:
        severity_color = {
            'Critical': '#fee2e2',
            'High': '#fed7aa',
            'Medium': '#fef3c7',
            'Low': '#dbeafe'
        }
        
        severity_text_color = {
            'Critical': '#991b1b',
            'High': '#9a3412',
            'Medium': '#92400e',
            'Low': '#1e40af'
        }
        
        with st.expander(f"**{finding['id']}** - {finding['title']} ({finding['severity']})", expanded=False):
            col1, col2 = st.columns([2, 1])
            
            with col1:
                st.markdown(f"""
                **Severity:** <span style="background: {severity_color[finding['severity']]}; 
                color: {severity_text_color[finding['severity']]}; padding: 0.25rem 0.75rem; 
                border-radius: 12px; font-size: 0.75rem; font-weight: 600;">
                {finding['severity']}</span>
                
                **Account:** `{finding['account']}`  
                **Resource:** `{finding['resource']}`  
                **Framework:** {finding['framework']}  
                **Control:** {finding['control']}  
                **Status:** {finding['status']}
                
                **Description:**  
                {finding['description']}
                
                **Recommendation:**  
                {finding['recommendation']}
                """, unsafe_allow_html=True)
            
            with col2:
                st.markdown("**Actions**")
                if st.button(f"🤖 Get AI Recommendation", key=f"ai_{finding['id']}"):
                    st.info("AI recommendation would be generated here...")
                if st.button(f"⚡ Auto-Remediate", key=f"rem_{finding['id']}"):
                    st.success("Remediation workflow initiated!")
                if st.button(f"📋 View Details", key=f"det_{finding['id']}"):
                    st.info("Detailed view would open here...")

def render_ai_intelligence():
    """Render the AI Intelligence view"""
    st.markdown("## 🤖 AI Intelligence & Recommendations")
    
    st.markdown("""
    The AI Intelligence layer uses AWS Bedrock with Claude AI to provide context-aware 
    security recommendations, vulnerability analysis, and automated remediation strategies.
    """)
    
    st.markdown("---")
    
    # AI Capabilities
    st.markdown("### AI-Powered Capabilities")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("""
        <div class="metric-card">
            <h4>🧠 Analysis Completed</h4>
            <h2 style="color: #3b82f6;">3,456</h2>
            <p style="font-size: 0.875rem; color: #6b7280;">Across all accounts</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown("""
        <div class="metric-card">
            <h4>💡 Recommendations Generated</h4>
            <h2 style="color: #22c55e;">892</h2>
            <p style="font-size: 0.875rem; color: #6b7280;">234 auto-approved</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown("""
        <div class="metric-card">
            <h4>📊 Accuracy Rate</h4>
            <h2 style="color: #eab308;">94%</h2>
            <p style="font-size: 0.875rem; color: #6b7280;">Verified effectiveness</p>
        </div>
        """, unsafe_allow_html=True)
    
    st.markdown("---")
    
    # Recent AI Recommendations
    st.markdown("### 🎯 Recent AI Recommendations")
    
    recommendations = [
        {
            'title': 'S3 Bucket Encryption Configuration',
            'finding': 'F001 - S3 Bucket Publicly Accessible',
            'confidence': 98,
            'impact': 'High',
            'recommendation': 'Enable default encryption with AWS KMS and block all public access at the bucket level. This will maintain data confidentiality while preventing unauthorized access.',
            'estimated_time': '5 minutes',
            'automation': 'Available'
        },
        {
            'title': 'MFA Enforcement Strategy',
            'finding': 'F002 - IAM User Without MFA',
            'confidence': 95,
            'impact': 'High',
            'recommendation': 'Implement organization-wide SCP to enforce MFA for console access. Create automated workflow to notify users and disable console access after 7 days grace period.',
            'estimated_time': '15 minutes',
            'automation': 'Partially Available'
        },
        {
            'title': 'EBS Volume Encryption Remediation',
            'finding': 'F003 - Unencrypted EBS Volume',
            'confidence': 92,
            'impact': 'Medium',
            'recommendation': 'Create encrypted snapshot, launch new volume from snapshot, and replace attachment. Minimal downtime approach available with step-by-step orchestration.',
            'estimated_time': '30 minutes',
            'automation': 'Available'
        }
    ]
    
    for rec in recommendations:
        with st.expander(f"**{rec['title']}** (Confidence: {rec['confidence']}%)", expanded=False):
            col1, col2 = st.columns([2, 1])
            
            with col1:
                st.markdown(f"""
                **Related Finding:** {rec['finding']}  
                **Impact:** {rec['impact']}  
                **Estimated Time:** {rec['estimated_time']}  
                **Automation:** {rec['automation']}
                
                **Recommendation:**  
                {rec['recommendation']}
                """)
            
            with col2:
                st.markdown(f"**Confidence Score**")
                st.progress(rec['confidence'] / 100)
                st.markdown(f"{rec['confidence']}%")
                
                if st.button(f"✅ Approve", key=f"app_{rec['title']}"):
                    st.success("Recommendation approved!")
                if st.button(f"⚡ Execute", key=f"exe_{rec['title']}"):
                    st.info("Executing remediation...")
    
    st.markdown("---")
    
    # AI Model Information
    st.markdown("### 🔧 AI Model Configuration")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        **Primary Model**  
        AWS Bedrock - Claude 3.5 Sonnet
        
        **Capabilities:**
        - Security finding analysis
        - Context-aware recommendations
        - Compliance mapping
        - Risk assessment
        - Remediation planning
        """)
    
    with col2:
        st.markdown("""
        **Knowledge Base**  
        RAG with 1,234 security documents
        
        **Sources:**
        - AWS Security Best Practices
        - Compliance Framework Documentation
        - Internal Security Playbooks
        - CVE Database
        - Threat Intelligence Feeds
        """)

def render_simulation():
    """Render the Live Simulation view"""
    st.markdown("## ⚡ Live Platform Simulation")
    
    st.markdown("""
    Watch the platform in action with a live simulation of security finding detection, 
    AI analysis, and automated remediation across the multi-account infrastructure.
    """)
    
    st.markdown("---")
    
    # Control panel
    col1, col2, col3, col4 = st.columns([1, 1, 1, 3])
    
    with col1:
        if st.button("▶️ Start", disabled=st.session_state.simulation_running, use_container_width=True):
            st.session_state.simulation_running = True
            st.session_state.findings = []
            st.session_state.remediation_logs = []
    
    with col2:
        if st.button("⏸️ Pause", disabled=not st.session_state.simulation_running, use_container_width=True):
            st.session_state.simulation_running = False
    
    with col3:
        if st.button("🔄 Reset", use_container_width=True):
            st.session_state.simulation_running = False
            st.session_state.findings = []
            st.session_state.remediation_logs = []
            st.rerun()
    
    st.markdown("---")
    
    # Simulation area
    if st.session_state.simulation_running:
        # Add a manual trigger button
        if st.button("🎲 Generate New Activity", use_container_width=True):
            # Generate new finding
            new_finding = random.choice(SAMPLE_FINDINGS)
            finding_with_time = {
                **new_finding,
                'detected_at': datetime.now().strftime("%H:%M:%S"),
                'ai_score': random.randint(85, 99)
            }
            st.session_state.findings.insert(0, finding_with_time)
            
            # Generate remediation log
            if random.random() > 0.5:
                remediation = {
                    'time': datetime.now().strftime("%H:%M:%S"),
                    'action': f"Auto-remediated {new_finding['title']}",
                    'account': new_finding['account'],
                    'status': 'Success'
                }
                st.session_state.remediation_logs.insert(0, remediation)
            
            st.rerun()
    
    # Display live findings
    if st.session_state.findings:
        st.markdown("### 🔔 Live Security Findings")
        
        for finding in st.session_state.findings[:5]:  # Show last 5
            severity_color = {
                'Critical': '#fee2e2',
                'High': '#fed7aa',
                'Medium': '#fef3c7',
                'Low': '#dbeafe'
            }
            
            st.markdown(f"""
            <div style="background: {severity_color[finding['severity']]}; 
            padding: 1rem; margin: 0.5rem 0; border-radius: 8px; border-left: 4px solid #ef4444;">
                <div style="display: flex; justify-content: space-between;">
                    <div>
                        <strong>{finding['detected_at']}</strong> - {finding['title']}
                        <br/><small>Account: {finding['account']} | AI Confidence: {finding['ai_score']}%</small>
                    </div>
                    <span style="background: white; padding: 0.25rem 0.75rem; border-radius: 12px; 
                    font-size: 0.75rem; font-weight: 600;">{finding['severity']}</span>
                </div>
            </div>
            """, unsafe_allow_html=True)
    
    st.markdown("---")
    
    # Display remediation logs
    if st.session_state.remediation_logs:
        st.markdown("### ✅ Remediation Activity")
        
        for log in st.session_state.remediation_logs[:5]:  # Show last 5
            st.markdown(f"""
            <div style="background: #d1fae5; padding: 1rem; margin: 0.5rem 0; 
            border-radius: 8px; border-left: 4px solid #10b981;">
                <strong>{log['time']}</strong> - {log['action']}
                <br/><small>Account: {log['account']} | Status: {log['status']}</small>
            </div>
            """, unsafe_allow_html=True)
    
    # Statistics
    if st.session_state.findings or st.session_state.remediation_logs:
        st.markdown("---")
        st.markdown("### 📊 Simulation Statistics")
        
        col1, col2, col3, col4 = st.columns(4)
        
        col1.metric("Total Findings", len(st.session_state.findings))
        col2.metric("Remediated", len(st.session_state.remediation_logs))
        col3.metric("Success Rate", f"{min(100, len(st.session_state.remediation_logs) / max(len(st.session_state.findings), 1) * 100):.0f}%")
        col4.metric("Avg Response Time", "2.3s")

# Main application
def main():
    render_header()
    
    # Navigation tabs
    tabs = st.tabs([
        "📊 Dashboard",
        "🔄 End-to-End Workflow",
        "🔍 Security Findings",
        "🤖 AI Intelligence",
        "⚡ Live Simulation"
    ])
    
    with tabs[0]:
        render_dashboard()
    
    with tabs[1]:
        render_e2e_workflow()
    
    with tabs[2]:
        render_findings()
    
    with tabs[3]:
        render_ai_intelligence()
    
    with tabs[4]:
        render_simulation()
    
    # Footer
    st.markdown("---")
    st.markdown("""
    <div style="text-align: center; padding: 2rem; color: #6b7280;">
        <p style="margin: 0;">
            <strong>Scalable Multi-Account Architecture</strong> • 
            Consistent Policy Enforcement • 
            Centralized Intelligence • 
            Real-Time Compliance
        </p>
        <div style="margin-top: 1rem; font-size: 0.875rem;">
            <span>🛡️ PCI DSS, HIPAA, GDPR, SOC 2</span> • 
            <span>🤖 AI-Powered Analysis</span> • 
            <span>⚡ Automated Remediation</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()
