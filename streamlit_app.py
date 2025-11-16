"""
AI-Enhanced AWS Compliance Platform
Multi-Account Security Monitoring with Claude AI

This Streamlit application provides real-time compliance monitoring,
security analysis, and AI-powered remediation recommendations for AWS accounts.
"""

import streamlit as st
import boto3
from botocore.exceptions import ClientError, NoCredentialsError
import anthropic
import json
import pandas as pd
from datetime import datetime, timedelta
import plotly.express as px
import plotly.graph_objects as go
from typing import Dict, List, Any, Optional
import time

# ============================================================================
# PAGE CONFIGURATION
# ============================================================================

st.set_page_config(
    page_title="AI-Enhanced AWS Compliance Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============================================================================
# CUSTOM CSS STYLING
# ============================================================================

st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1f77b4;
        text-align: center;
        padding: 1rem 0;
    }
    .sub-header {
        font-size: 1.2rem;
        color: #666;
        text-align: center;
        margin-bottom: 2rem;
    }
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 1.5rem;
        border-radius: 10px;
        color: white;
        margin: 0.5rem 0;
    }
    .critical-finding {
        background-color: #ff4444;
        padding: 1rem;
        border-radius: 5px;
        margin: 0.5rem 0;
        color: white;
    }
    .high-finding {
        background-color: #ff8800;
        padding: 1rem;
        border-radius: 5px;
        margin: 0.5rem 0;
        color: white;
    }
    .medium-finding {
        background-color: #ffbb33;
        padding: 1rem;
        border-radius: 5px;
        margin: 0.5rem 0;
    }
    .low-finding {
        background-color: #00C851;
        padding: 1rem;
        border-radius: 5px;
        margin: 0.5rem 0;
        color: white;
    }
    .ai-analysis {
        background-color: #f0f8ff;
        border-left: 5px solid #1f77b4;
        padding: 1rem;
        margin: 1rem 0;
        border-radius: 5px;
    }
    .stButton>button {
        width: 100%;
    }
</style>
""", unsafe_allow_html=True)

# ============================================================================
# CONFIGURATION AND SESSION STATE
# ============================================================================

def initialize_session_state():
    """Initialize Streamlit session state variables"""
    if 'aws_client_initialized' not in st.session_state:
        st.session_state.aws_client_initialized = False
    if 'claude_client_initialized' not in st.session_state:
        st.session_state.claude_client_initialized = False
    if 'security_findings' not in st.session_state:
        st.session_state.security_findings = []
    if 'config_compliance' not in st.session_state:
        st.session_state.config_compliance = {}
    if 'guardduty_findings' not in st.session_state:
        st.session_state.guardduty_findings = []
    if 'ai_analysis_cache' not in st.session_state:
        st.session_state.ai_analysis_cache = {}

# ============================================================================
# AWS CLIENT INITIALIZATION
# ============================================================================

@st.cache_resource
def get_aws_clients(aws_access_key: str, aws_secret_key: str, region: str):
    """Initialize AWS service clients"""
    try:
        session = boto3.Session(
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key,
            region_name=region
        )
        
        clients = {
            'securityhub': session.client('securityhub'),
            'config': session.client('config'),
            'guardduty': session.client('guardduty'),
            'organizations': session.client('organizations'),
            'sts': session.client('sts')
        }
        
        return clients
    except Exception as e:
        st.error(f"Failed to initialize AWS clients: {str(e)}")
        return None

# ============================================================================
# CLAUDE API CLIENT
# ============================================================================

@st.cache_resource
def get_claude_client(api_key: str):
    """Initialize Anthropic Claude client"""
    try:
        client = anthropic.Anthropic(api_key=api_key)
        return client
    except Exception as e:
        st.error(f"Failed to initialize Claude client: {str(e)}")
        return None

# ============================================================================
# AWS DATA FETCHING FUNCTIONS
# ============================================================================

def get_security_hub_findings(securityhub_client, max_results: int = 100) -> List[Dict]:
    """Fetch findings from AWS Security Hub"""
    try:
        findings = []
        paginator = securityhub_client.get_paginator('get_findings')
        
        # Filter for active findings only
        filters = {
            'RecordState': [{'Value': 'ACTIVE', 'Comparison': 'EQUALS'}]
        }
        
        page_iterator = paginator.paginate(
            Filters=filters,
            MaxResults=max_results
        )
        
        for page in page_iterator:
            findings.extend(page['Findings'])
        
        return findings
    except ClientError as e:
        st.error(f"Error fetching Security Hub findings: {str(e)}")
        return []

def get_config_compliance_summary(config_client) -> Dict:
    """Get AWS Config compliance summary"""
    try:
        response = config_client.describe_compliance_by_config_rule()
        
        compliance_summary = {
            'COMPLIANT': 0,
            'NON_COMPLIANT': 0,
            'NOT_APPLICABLE': 0,
            'INSUFFICIENT_DATA': 0
        }
        
        for rule in response.get('ComplianceByConfigRules', []):
            compliance = rule.get('Compliance', {})
            compliance_type = compliance.get('ComplianceType', 'INSUFFICIENT_DATA')
            compliance_summary[compliance_type] = compliance_summary.get(compliance_type, 0) + 1
        
        return compliance_summary
    except ClientError as e:
        st.error(f"Error fetching Config compliance: {str(e)}")
        return {}

def get_guardduty_findings(guardduty_client) -> List[Dict]:
    """Fetch findings from AWS GuardDuty"""
    try:
        # First, get list of detectors
        detectors_response = guardduty_client.list_detectors()
        detector_ids = detectors_response.get('DetectorIds', [])
        
        if not detector_ids:
            return []
        
        all_findings = []
        
        for detector_id in detector_ids:
            # Get finding IDs
            findings_response = guardduty_client.list_findings(
                DetectorId=detector_id,
                FindingCriteria={
                    'Criterion': {
                        'service.archived': {
                            'Eq': ['false']
                        }
                    }
                },
                MaxResults=50
            )
            
            finding_ids = findings_response.get('FindingIds', [])
            
            if finding_ids:
                # Get finding details
                findings_detail = guardduty_client.get_findings(
                    DetectorId=detector_id,
                    FindingIds=finding_ids
                )
                all_findings.extend(findings_detail.get('Findings', []))
        
        return all_findings
    except ClientError as e:
        st.error(f"Error fetching GuardDuty findings: {str(e)}")
        return []

def get_account_info(sts_client) -> Dict:
    """Get current AWS account information"""
    try:
        response = sts_client.get_caller_identity()
        return {
            'AccountId': response.get('Account'),
            'Arn': response.get('Arn'),
            'UserId': response.get('UserId')
        }
    except ClientError as e:
        st.error(f"Error getting account info: {str(e)}")
        return {}

# ============================================================================
# CLAUDE AI ANALYSIS FUNCTIONS
# ============================================================================

def analyze_finding_with_claude(claude_client, finding: Dict, finding_type: str = "SecurityHub") -> str:
    """Use Claude AI to analyze a security finding and provide recommendations"""
    
    # Create a cache key for this finding
    cache_key = f"{finding_type}_{finding.get('Id', '')}_{finding.get('GeneratorId', '')}"
    
    # Check if we have cached analysis
    if cache_key in st.session_state.ai_analysis_cache:
        return st.session_state.ai_analysis_cache[cache_key]
    
    try:
        # Prepare the finding details for Claude
        if finding_type == "SecurityHub":
            finding_context = f"""
Security Finding Analysis Request:

Finding ID: {finding.get('Id', 'Unknown')}
Title: {finding.get('Title', 'Unknown')}
Severity: {finding.get('Severity', {}).get('Label', 'Unknown')}
Compliance Status: {finding.get('Compliance', {}).get('Status', 'Unknown')}
Description: {finding.get('Description', 'No description available')}

Resources Affected:
{json.dumps(finding.get('Resources', []), indent=2)}

Recommendation from AWS:
{finding.get('Remediation', {}).get('Recommendation', {}).get('Text', 'No recommendation provided')}

Compliance Frameworks:
{json.dumps(finding.get('Compliance', {}), indent=2)}
"""
        else:  # GuardDuty
            finding_context = f"""
Security Threat Analysis Request:

Finding ID: {finding.get('Id', 'Unknown')}
Type: {finding.get('Type', 'Unknown')}
Severity: {finding.get('Severity', 'Unknown')}
Title: {finding.get('Title', 'Unknown')}
Description: {finding.get('Description', 'No description available')}

Resource: {json.dumps(finding.get('Resource', {}), indent=2)}
Service: {json.dumps(finding.get('Service', {}), indent=2)}
"""

        prompt = f"""{finding_context}

As a senior security engineer analyzing this AWS security finding, please provide:

1. **Risk Assessment**: Evaluate the true severity and potential business impact
2. **Root Cause Analysis**: Identify the underlying cause of this security issue
3. **Attack Vectors**: Describe potential attack scenarios if this issue is exploited
4. **Compliance Impact**: Identify which compliance frameworks (PCI DSS, HIPAA, GDPR, SOC 2) are affected
5. **Remediation Plan**: Provide step-by-step remediation with specific AWS CLI commands or CloudFormation templates
6. **Prevention Strategy**: Suggest preventive controls to avoid similar issues in the future

Please be concise but thorough in your analysis."""

        message = claude_client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2000,
            temperature=0.3,
            messages=[
                {"role": "user", "content": prompt}
            ]
        )
        
        analysis = message.content[0].text
        
        # Cache the analysis
        st.session_state.ai_analysis_cache[cache_key] = analysis
        
        return analysis
        
    except Exception as e:
        error_msg = f"Error during Claude AI analysis: {str(e)}"
        st.error(error_msg)
        return error_msg

def get_compliance_insights(claude_client, compliance_data: Dict, findings_summary: Dict) -> str:
    """Get AI-powered compliance insights and recommendations"""
    try:
        prompt = f"""
As a compliance and security expert, analyze the following AWS compliance data:

Config Rules Compliance Summary:
- Compliant Rules: {compliance_data.get('COMPLIANT', 0)}
- Non-Compliant Rules: {compliance_data.get('NON_COMPLIANT', 0)}
- Not Applicable: {compliance_data.get('NOT_APPLICABLE', 0)}
- Insufficient Data: {compliance_data.get('INSUFFICIENT_DATA', 0)}

Security Findings Summary:
{json.dumps(findings_summary, indent=2)}

Please provide:

1. **Overall Compliance Posture**: Assessment of the current security and compliance state
2. **Critical Gaps**: Identify the most critical compliance gaps that need immediate attention
3. **Risk Prioritization**: Prioritize risks based on severity and compliance impact
4. **Quick Wins**: Suggest quick remediation actions that can improve compliance score rapidly
5. **Strategic Recommendations**: Long-term improvements for maintaining strong security posture
6. **Compliance Framework Alignment**: How well does this align with PCI DSS, HIPAA, GDPR, and SOC 2 requirements?

Be specific and actionable in your recommendations.
"""

        message = claude_client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2500,
            temperature=0.3,
            messages=[
                {"role": "user", "content": prompt}
            ]
        )
        
        return message.content[0].text
        
    except Exception as e:
        return f"Error generating compliance insights: {str(e)}"

def generate_remediation_code(claude_client, finding: Dict) -> str:
    """Generate executable remediation code using Claude"""
    try:
        prompt = f"""
Generate Python boto3 code to automatically remediate this AWS security finding:

Finding Title: {finding.get('Title', 'Unknown')}
Description: {finding.get('Description', 'Unknown')}
Resource: {json.dumps(finding.get('Resources', [{}])[0], indent=2)}
Recommendation: {finding.get('Remediation', {}).get('Recommendation', {}).get('Text', 'Unknown')}

Please provide:
1. Complete, executable Python code using boto3
2. Proper error handling
3. Dry-run option for testing
4. Rollback procedure
5. Comments explaining each step

The code should be production-ready and follow AWS best practices.
"""

        message = claude_client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2000,
            temperature=0.2,
            messages=[
                {"role": "user", "content": prompt}
            ]
        )
        
        return message.content[0].text
        
    except Exception as e:
        return f"Error generating remediation code: {str(e)}"

# ============================================================================
# DATA PROCESSING FUNCTIONS
# ============================================================================

def process_findings_for_display(findings: List[Dict]) -> pd.DataFrame:
    """Convert Security Hub findings to DataFrame for display"""
    if not findings:
        return pd.DataFrame()
    
    processed = []
    for finding in findings:
        processed.append({
            'ID': finding.get('Id', 'Unknown')[:50] + '...',
            'Title': finding.get('Title', 'Unknown'),
            'Severity': finding.get('Severity', {}).get('Label', 'Unknown'),
            'Status': finding.get('Compliance', {}).get('Status', 'Unknown'),
            'Resource': finding.get('Resources', [{}])[0].get('Type', 'Unknown'),
            'Created': finding.get('CreatedAt', 'Unknown')[:10],
            'Updated': finding.get('UpdatedAt', 'Unknown')[:10],
        })
    
    return pd.DataFrame(processed)

def get_severity_counts(findings: List[Dict]) -> Dict:
    """Count findings by severity"""
    counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFORMATIONAL': 0}
    for finding in findings:
        severity = finding.get('Severity', {}).get('Label', 'INFORMATIONAL')
        counts[severity] = counts.get(severity, 0) + 1
    return counts

def get_compliance_status_counts(findings: List[Dict]) -> Dict:
    """Count findings by compliance status"""
    counts = {}
    for finding in findings:
        status = finding.get('Compliance', {}).get('Status', 'UNKNOWN')
        counts[status] = counts.get(status, 0) + 1
    return counts

# ============================================================================
# VISUALIZATION FUNCTIONS
# ============================================================================

def create_severity_chart(severity_counts: Dict):
    """Create a pie chart for severity distribution"""
    df = pd.DataFrame(list(severity_counts.items()), columns=['Severity', 'Count'])
    df = df[df['Count'] > 0]  # Only show non-zero counts
    
    colors = {
        'CRITICAL': '#8B0000',
        'HIGH': '#FF4444',
        'MEDIUM': '#FFBB33',
        'LOW': '#00C851',
        'INFORMATIONAL': '#33B5E5'
    }
    
    color_sequence = [colors.get(severity, '#CCCCCC') for severity in df['Severity']]
    
    fig = px.pie(df, values='Count', names='Severity', 
                 title='Security Findings by Severity',
                 color_discrete_sequence=color_sequence)
    fig.update_traces(textposition='inside', textinfo='percent+label+value')
    return fig

def create_compliance_chart(compliance_data: Dict):
    """Create a bar chart for compliance status"""
    df = pd.DataFrame(list(compliance_data.items()), columns=['Status', 'Count'])
    
    colors = {
        'COMPLIANT': '#00C851',
        'NON_COMPLIANT': '#FF4444',
        'NOT_APPLICABLE': '#CCCCCC',
        'INSUFFICIENT_DATA': '#FFBB33'
    }
    
    fig = px.bar(df, x='Status', y='Count', 
                 title='AWS Config Rules Compliance Status',
                 color='Status',
                 color_discrete_map=colors)
    fig.update_layout(showlegend=False)
    return fig

def create_timeline_chart(findings: List[Dict]):
    """Create timeline of findings"""
    if not findings:
        return None
    
    dates = []
    for finding in findings:
        created = finding.get('CreatedAt', '')
        if created:
            dates.append(created[:10])
    
    if not dates:
        return None
    
    df = pd.DataFrame({'Date': dates})
    df['Count'] = 1
    df = df.groupby('Date').count().reset_index()
    df = df.sort_values('Date')
    
    fig = px.line(df, x='Date', y='Count', 
                  title='Security Findings Over Time',
                  markers=True)
    return fig

# ============================================================================
# SIDEBAR - CONFIGURATION
# ============================================================================

def render_sidebar():
    """Render the configuration sidebar"""
    with st.sidebar:
        st.markdown("## ⚙️ Configuration")
        
        st.markdown("### 🔑 Anthropic Claude API")
        claude_api_key = st.text_input(
            "Claude API Key",
            type="password",
            help="Enter your Anthropic API key",
            key="claude_api_key"
        )
        
        st.markdown("### ☁️ AWS Credentials")
        aws_access_key = st.text_input(
            "AWS Access Key ID",
            type="password",
            help="Enter your AWS Access Key ID",
            key="aws_access_key"
        )
        
        aws_secret_key = st.text_input(
            "AWS Secret Access Key",
            type="password",
            help="Enter your AWS Secret Access Key",
            key="aws_secret_key"
        )
        
        aws_region = st.selectbox(
            "AWS Region",
            ["us-east-1", "us-east-2", "us-west-1", "us-west-2", 
             "eu-west-1", "eu-central-1", "ap-southeast-1", "ap-northeast-1"],
            help="Select your AWS region",
            key="aws_region"
        )
        
        st.markdown("---")
        
        if st.button("🚀 Initialize Clients", use_container_width=True):
            with st.spinner("Initializing AWS and Claude clients..."):
                # Initialize Claude client
                if claude_api_key:
                    claude_client = get_claude_client(claude_api_key)
                    if claude_client:
                        st.session_state.claude_client = claude_client
                        st.session_state.claude_client_initialized = True
                        st.success("✅ Claude client initialized!")
                else:
                    st.error("❌ Please provide Claude API key")
                
                # Initialize AWS clients
                if aws_access_key and aws_secret_key:
                    aws_clients = get_aws_clients(aws_access_key, aws_secret_key, aws_region)
                    if aws_clients:
                        st.session_state.aws_clients = aws_clients
                        st.session_state.aws_client_initialized = True
                        st.success("✅ AWS clients initialized!")
                        
                        # Get account info
                        account_info = get_account_info(aws_clients['sts'])
                        st.session_state.account_info = account_info
                else:
                    st.error("❌ Please provide AWS credentials")
        
        st.markdown("---")
        
        # Display connection status
        st.markdown("### 📊 Connection Status")
        
        if st.session_state.get('claude_client_initialized', False):
            st.success("🟢 Claude API Connected")
        else:
            st.error("🔴 Claude API Not Connected")
        
        if st.session_state.get('aws_client_initialized', False):
            st.success("🟢 AWS Connected")
            if 'account_info' in st.session_state:
                st.info(f"Account: {st.session_state.account_info.get('AccountId', 'Unknown')}")
        else:
            st.error("🔴 AWS Not Connected")
        
        st.markdown("---")
        
        # Refresh data button
        if st.session_state.get('aws_client_initialized', False):
            if st.button("🔄 Refresh Data", use_container_width=True):
                st.rerun()

# ============================================================================
# MAIN DASHBOARD
# ============================================================================

def render_overview_dashboard():
    """Render the main overview dashboard"""
    st.markdown('<div class="main-header">🛡️ AI-Enhanced AWS Compliance Platform</div>', 
                unsafe_allow_html=True)
    st.markdown('<div class="sub-header">Multi-Account Security Monitoring with Claude AI</div>', 
                unsafe_allow_html=True)
    
    if not st.session_state.get('aws_client_initialized', False):
        st.warning("⚠️ Please configure AWS credentials in the sidebar to get started")
        return
    
    # Fetch data from AWS
    with st.spinner("🔍 Fetching security data from AWS..."):
        aws_clients = st.session_state.aws_clients
        
        # Get Security Hub findings
        security_findings = get_security_hub_findings(aws_clients['securityhub'])
        st.session_state.security_findings = security_findings
        
        # Get Config compliance
        config_compliance = get_config_compliance_summary(aws_clients['config'])
        st.session_state.config_compliance = config_compliance
        
        # Get GuardDuty findings
        guardduty_findings = get_guardduty_findings(aws_clients['guardduty'])
        st.session_state.guardduty_findings = guardduty_findings
    
    # Display key metrics
    st.markdown("## 📊 Security Posture Overview")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        total_findings = len(security_findings)
        st.metric(
            label="Total Security Findings",
            value=total_findings,
            delta=f"Active",
            delta_color="inverse"
        )
    
    with col2:
        severity_counts = get_severity_counts(security_findings)
        critical_high = severity_counts.get('CRITICAL', 0) + severity_counts.get('HIGH', 0)
        st.metric(
            label="Critical + High Severity",
            value=critical_high,
            delta="Requires attention" if critical_high > 0 else "Good",
            delta_color="inverse" if critical_high > 0 else "normal"
        )
    
    with col3:
        compliant = config_compliance.get('COMPLIANT', 0)
        non_compliant = config_compliance.get('NON_COMPLIANT', 0)
        total_rules = compliant + non_compliant
        compliance_rate = (compliant / total_rules * 100) if total_rules > 0 else 0
        st.metric(
            label="Compliance Rate",
            value=f"{compliance_rate:.1f}%",
            delta=f"{compliant}/{total_rules} rules"
        )
    
    with col4:
        guardduty_count = len(guardduty_findings)
        st.metric(
            label="GuardDuty Threats",
            value=guardduty_count,
            delta="Active threats" if guardduty_count > 0 else "No threats",
            delta_color="inverse" if guardduty_count > 0 else "normal"
        )
    
    # Visualization row
    st.markdown("---")
    col1, col2 = st.columns(2)
    
    with col1:
        severity_chart = create_severity_chart(severity_counts)
        if severity_chart:
            st.plotly_chart(severity_chart, use_container_width=True)
    
    with col2:
        compliance_chart = create_compliance_chart(config_compliance)
        if compliance_chart:
            st.plotly_chart(compliance_chart, use_container_width=True)
    
    # Timeline
    timeline = create_timeline_chart(security_findings)
    if timeline:
        st.plotly_chart(timeline, use_container_width=True)
    
    # AI-Powered Compliance Insights
    if st.session_state.get('claude_client_initialized', False):
        st.markdown("---")
        st.markdown("## 🤖 AI-Powered Compliance Insights")
        
        if st.button("🧠 Generate Comprehensive Compliance Analysis", use_container_width=True):
            with st.spinner("🤖 Claude AI is analyzing your compliance posture..."):
                findings_summary = {
                    'total_findings': len(security_findings),
                    'severity_distribution': severity_counts,
                    'compliance_status': get_compliance_status_counts(security_findings),
                    'guardduty_threats': len(guardduty_findings)
                }
                
                insights = get_compliance_insights(
                    st.session_state.claude_client,
                    config_compliance,
                    findings_summary
                )
                
                st.markdown('<div class="ai-analysis">', unsafe_allow_html=True)
                st.markdown("### 📋 Claude's Analysis")
                st.markdown(insights)
                st.markdown('</div>', unsafe_allow_html=True)

def render_findings_detail():
    """Render detailed findings view with AI analysis"""
    st.markdown("## 🔍 Security Findings Details")
    
    if not st.session_state.get('aws_client_initialized', False):
        st.warning("⚠️ Please configure AWS credentials in the sidebar")
        return
    
    security_findings = st.session_state.get('security_findings', [])
    
    if not security_findings:
        st.info("ℹ️ No security findings to display")
        return
    
    # Filter options
    col1, col2, col3 = st.columns(3)
    
    with col1:
        severity_filter = st.multiselect(
            "Filter by Severity",
            ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL'],
            default=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL']
        )
    
    with col2:
        compliance_filter = st.multiselect(
            "Filter by Compliance Status",
            ['PASSED', 'FAILED', 'WARNING', 'NOT_AVAILABLE'],
            default=['PASSED', 'FAILED', 'WARNING', 'NOT_AVAILABLE']
        )
    
    with col3:
        max_findings = st.slider("Max findings to display", 10, 100, 50)
    
    # Filter findings
    filtered_findings = [
        f for f in security_findings
        if f.get('Severity', {}).get('Label', '') in severity_filter
        and f.get('Compliance', {}).get('Status', '') in compliance_filter
    ][:max_findings]
    
    # Display findings table
    df = process_findings_for_display(filtered_findings)
    if not df.empty:
        st.dataframe(df, use_container_width=True, height=400)
    
    # Detailed finding analysis
    st.markdown("---")
    st.markdown("### 🎯 Deep Dive Analysis")
    
    if filtered_findings and st.session_state.get('claude_client_initialized', False):
        selected_finding_idx = st.selectbox(
            "Select a finding for AI analysis",
            range(len(filtered_findings)),
            format_func=lambda x: f"{filtered_findings[x].get('Title', 'Unknown')} - {filtered_findings[x].get('Severity', {}).get('Label', 'Unknown')}"
        )
        
        selected_finding = filtered_findings[selected_finding_idx]
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("#### 📄 Finding Details")
            st.json(selected_finding)
        
        with col2:
            st.markdown("#### 🤖 AI Analysis & Remediation")
            
            if st.button("🧠 Analyze with Claude AI", key="analyze_finding"):
                with st.spinner("🤖 Claude is analyzing this finding..."):
                    analysis = analyze_finding_with_claude(
                        st.session_state.claude_client,
                        selected_finding,
                        "SecurityHub"
                    )
                    
                    st.markdown('<div class="ai-analysis">', unsafe_allow_html=True)
                    st.markdown(analysis)
                    st.markdown('</div>', unsafe_allow_html=True)
            
            if st.button("💻 Generate Remediation Code", key="generate_code"):
                with st.spinner("🤖 Generating remediation code..."):
                    code = generate_remediation_code(
                        st.session_state.claude_client,
                        selected_finding
                    )
                    
                    st.markdown("##### Automated Remediation Code")
                    st.code(code, language="python")

def render_compliance_framework():
    """Render compliance framework monitoring"""
    st.markdown("## 📋 Compliance Framework Monitoring")
    
    if not st.session_state.get('aws_client_initialized', False):
        st.warning("⚠️ Please configure AWS credentials in the sidebar")
        return
    
    # Compliance frameworks
    frameworks = {
        'PCI DSS': {
            'description': 'Payment Card Industry Data Security Standard',
            'color': '#FF6384',
            'key_controls': ['Encryption', 'Access Control', 'Monitoring', 'Network Security']
        },
        'HIPAA': {
            'description': 'Health Insurance Portability and Accountability Act',
            'color': '#36A2EB',
            'key_controls': ['Data Privacy', 'Security', 'Breach Notification', 'Audit Controls']
        },
        'GDPR': {
            'description': 'General Data Protection Regulation',
            'color': '#FFCE56',
            'key_controls': ['Data Protection', 'Privacy by Design', 'Right to be Forgotten', 'Data Portability']
        },
        'SOC 2': {
            'description': 'Service Organization Control 2',
            'color': '#4BC0C0',
            'key_controls': ['Security', 'Availability', 'Processing Integrity', 'Confidentiality']
        }
    }
    
    # Display framework cards
    cols = st.columns(2)
    
    for idx, (framework, details) in enumerate(frameworks.items()):
        with cols[idx % 2]:
            st.markdown(f"### {framework}")
            st.markdown(f"*{details['description']}*")
            
            # Simulate compliance score (in real implementation, this would be calculated from findings)
            config_compliance = st.session_state.get('config_compliance', {})
            compliant = config_compliance.get('COMPLIANT', 0)
            total = sum(config_compliance.values()) if config_compliance else 1
            score = (compliant / total * 100) if total > 0 else 0
            
            st.progress(score / 100)
            st.markdown(f"**Compliance Score: {score:.1f}%**")
            
            with st.expander("Key Controls"):
                for control in details['key_controls']:
                    st.markdown(f"- {control}")

def render_guardduty_threats():
    """Render GuardDuty threat monitoring"""
    st.markdown("## 🚨 GuardDuty Threat Detection")
    
    if not st.session_state.get('aws_client_initialized', False):
        st.warning("⚠️ Please configure AWS credentials in the sidebar")
        return
    
    guardduty_findings = st.session_state.get('guardduty_findings', [])
    
    if not guardduty_findings:
        st.success("✅ No active threats detected by GuardDuty!")
        return
    
    st.warning(f"⚠️ {len(guardduty_findings)} active threats detected")
    
    # Display threat summary
    for idx, finding in enumerate(guardduty_findings[:10]):  # Show top 10
        severity = finding.get('Severity', 0)
        
        severity_class = 'critical-finding' if severity >= 7 else \
                        'high-finding' if severity >= 4 else \
                        'medium-finding' if severity >= 2 else 'low-finding'
        
        st.markdown(f'<div class="{severity_class}">', unsafe_allow_html=True)
        st.markdown(f"**{finding.get('Title', 'Unknown Threat')}**")
        st.markdown(f"Severity: {severity}/10 | Type: {finding.get('Type', 'Unknown')}")
        st.markdown(f"Description: {finding.get('Description', 'No description')}")
        st.markdown('</div>', unsafe_allow_html=True)
        
        if st.session_state.get('claude_client_initialized', False):
            if st.button(f"🤖 Analyze Threat #{idx+1}", key=f"threat_{idx}"):
                with st.spinner("Analyzing threat..."):
                    analysis = analyze_finding_with_claude(
                        st.session_state.claude_client,
                        finding,
                        "GuardDuty"
                    )
                    st.markdown('<div class="ai-analysis">', unsafe_allow_html=True)
                    st.markdown(analysis)
                    st.markdown('</div>', unsafe_allow_html=True)

# ============================================================================
# MAIN APPLICATION
# ============================================================================

def main():
    """Main application entry point"""
    initialize_session_state()
    
    # Render sidebar
    render_sidebar()
    
    # Main navigation
    tab1, tab2, tab3, tab4 = st.tabs([
        "📊 Overview Dashboard",
        "🔍 Security Findings",
        "📋 Compliance Frameworks",
        "🚨 Threat Detection"
    ])
    
    with tab1:
        render_overview_dashboard()
    
    with tab2:
        render_findings_detail()
    
    with tab3:
        render_compliance_framework()
    
    with tab4:
        render_guardduty_threats()
    
    # Footer
    st.markdown("---")
    st.markdown("""
    <div style='text-align: center; color: #666; padding: 2rem;'>
        <p><strong>AI-Enhanced AWS Compliance Platform</strong></p>
        <p>Powered by Anthropic Claude AI | Multi-Account Security Monitoring</p>
        <p style='font-size: 0.8rem;'>⚠️ Ensure your AWS IAM user has appropriate permissions for Security Hub, Config, and GuardDuty</p>
    </div>
    """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()
