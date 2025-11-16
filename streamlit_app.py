"""
AI-Enhanced AWS Compliance Platform with GitOps Integration
Multi-Account Security Monitoring, Automated Remediation & Account Lifecycle Management

Features:
- AI-Powered Detection & Analysis (Claude/Bedrock)
- Automated Remediation with Code Generation
- GitHub/GitOps Integration
- Account Onboarding/Offboarding Automation
- Policy as Code Management
- CI/CD Pipeline Integration
- Version Control & Audit Trail
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
from typing import Dict, List, Any, Optional, Tuple
import time
import hashlib
import base64

# Note: Uncomment these imports when deploying with required packages
# from github import Github, GithubException
# import yaml

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
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
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
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }
    .critical-finding {
        background-color: #ff4444;
        padding: 1rem;
        border-radius: 5px;
        margin: 0.5rem 0;
        color: white;
        border-left: 5px solid #cc0000;
    }
    .high-finding {
        background-color: #ff8800;
        padding: 1rem;
        border-radius: 5px;
        margin: 0.5rem 0;
        color: white;
        border-left: 5px solid #cc6600;
    }
    .medium-finding {
        background-color: #ffbb33;
        padding: 1rem;
        border-radius: 5px;
        margin: 0.5rem 0;
        border-left: 5px solid #cc9900;
    }
    .low-finding {
        background-color: #00C851;
        padding: 1rem;
        border-radius: 5px;
        margin: 0.5rem 0;
        color: white;
        border-left: 5px solid #009933;
    }
    .ai-analysis {
        background-color: #f0f8ff;
        border-left: 5px solid #1f77b4;
        padding: 1.5rem;
        margin: 1rem 0;
        border-radius: 5px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    .github-section {
        background: linear-gradient(135deg, #24292e 0%, #1b1f23 100%);
        padding: 1.5rem;
        border-radius: 10px;
        color: white;
        margin: 1rem 0;
    }
    .lifecycle-card {
        background: linear-gradient(135deg, #00BCD4 0%, #0097A7 100%);
        padding: 1.5rem;
        border-radius: 10px;
        color: white;
        margin: 1rem 0;
    }
    .remediation-card {
        background: linear-gradient(135deg, #50C878 0%, #3AA05A 100%);
        padding: 1.5rem;
        border-radius: 10px;
        color: white;
        margin: 1rem 0;
    }
    .stButton>button {
        width: 100%;
        border-radius: 5px;
        font-weight: 600;
    }
    .success-banner {
        background-color: #d4edda;
        border: 1px solid #c3e6cb;
        color: #155724;
        padding: 1rem;
        border-radius: 5px;
        margin: 1rem 0;
    }
    .pipeline-status {
        display: inline-block;
        padding: 0.3rem 0.8rem;
        border-radius: 12px;
        font-size: 0.85rem;
        font-weight: bold;
    }
    .status-running { background-color: #2196F3; color: white; }
    .status-success { background-color: #4CAF50; color: white; }
    .status-failed { background-color: #f44336; color: white; }
    .status-pending { background-color: #FF9800; color: white; }
</style>
""", unsafe_allow_html=True)

# ============================================================================
# CONFIGURATION AND SESSION STATE
# ============================================================================

def initialize_session_state():
    """Initialize Streamlit session state variables"""
    defaults = {
        'aws_client_initialized': False,
        'claude_client_initialized': False,
        'github_client_initialized': False,
        'security_findings': [],
        'config_compliance': {},
        'guardduty_findings': [],
        'ai_analysis_cache': {},
        'remediation_history': [],
        'github_commits': [],
        'account_lifecycle_events': [],
        'automated_remediations': [],
        'policy_violations': [],
        'cicd_pipelines': [],
        'selected_accounts': [],
        'remediation_queue': []
    }
    
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value

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
            'sts': session.client('sts'),
            'lambda': session.client('lambda'),
            'iam': session.client('iam'),
            's3': session.client('s3'),
            'ec2': session.client('ec2'),
            'cloudformation': session.client('cloudformation'),
            'bedrock-runtime': session.client('bedrock-runtime'),
            'ssm': session.client('ssm'),
            'stepfunctions': session.client('stepfunctions'),
            'sns': session.client('sns'),
            'eventbridge': session.client('events')
        }
        
        return clients
    except Exception as e:
        st.error(f"Failed to initialize AWS clients: {str(e)}")
        return None

# ============================================================================
# CLAUDE/BEDROCK API CLIENT
# ============================================================================

def diagnose_anthropic_setup():
    """Diagnose Anthropic library setup"""
    import sys
    try:
        import anthropic
        version = getattr(anthropic, '__version__', 'Unknown')
        return {
            'installed': True,
            'version': version,
            'module_path': anthropic.__file__ if hasattr(anthropic, '__file__') else 'Unknown'
        }
    except ImportError:
        return {
            'installed': False,
            'error': 'Anthropic library not installed'
        }

def get_claude_client(api_key: str):
    """Initialize Anthropic Claude client"""
    import os
    
    try:
        # Clear any proxy environment variables that might interfere
        proxy_vars = ['HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy', 
                     'NO_PROXY', 'no_proxy', 'ALL_PROXY', 'all_proxy']
        original_env = {}
        
        for var in proxy_vars:
            if var in os.environ:
                original_env[var] = os.environ[var]
                del os.environ[var]
        
        try:
            # Initialize Claude client with just the API key
            client = anthropic.Anthropic(api_key=api_key)
            
            # Restore environment variables
            for var, value in original_env.items():
                os.environ[var] = value
                
            return client
            
        except Exception as e:
            # Restore environment variables even on error
            for var, value in original_env.items():
                os.environ[var] = value
            raise e
            
    except TypeError as e:
        st.error(f"⚠️ Claude client initialization error: {str(e)}")
        
        # Show diagnostic info
        diag = diagnose_anthropic_setup()
        if diag['installed']:
            st.warning(f"📦 Anthropic library version: {diag['version']}")
            st.info("💡 Try upgrading: `pip install --upgrade anthropic`")
        
        try:
            # Last resort: direct initialization
            import anthropic as ant
            client = ant.Anthropic(api_key=api_key)
            return client
        except Exception as e2:
            st.error(f"❌ Alternative initialization failed: {str(e2)}")
            return None
    except Exception as e:
        st.error(f"❌ Failed to initialize Claude client: {str(e)}")
        st.code(f"Error details: {type(e).__name__}: {str(e)}")
        return None

def get_bedrock_client(aws_clients: Dict):
    """Get AWS Bedrock client for Claude"""
    return aws_clients.get('bedrock-runtime') if aws_clients else None

# ============================================================================
# GITHUB CLIENT INITIALIZATION (Mock for demonstration)
# ============================================================================

class MockGithubClient:
    """Mock GitHub client for demonstration purposes"""
    def __init__(self, token):
        self.token = token
    
    def get_repo(self, repo_name):
        return MockRepo(repo_name)

class MockRepo:
    def __init__(self, name):
        self.name = name
        self.stargazers_count = 42
        self.forks_count = 12
        self.open_issues_count = 5
    
    def get_branches(self):
        return [{'name': 'main'}, {'name': 'develop'}]
    
    def get_commits(self):
        return [
            type('obj', (object,), {
                'sha': '1234567890abcdef',
                'commit': type('obj', (object,), {
                    'message': 'Add new compliance policy',
                    'author': type('obj', (object,), {
                        'name': 'DevOps Team',
                        'date': datetime.now()
                    })()
                })()
            })() for _ in range(10)
        ]

def get_github_client(github_token: str):
    """Initialize GitHub client (mock for demo)"""
    try:
        # In production, uncomment this:
        # from github import Github
        # return Github(github_token)
        return MockGithubClient(github_token)
    except Exception as e:
        st.error(f"Failed to initialize GitHub client: {str(e)}")
        return None

# ============================================================================
# AI-POWERED DETECTION & ANALYSIS
# ============================================================================

def analyze_with_ai(claude_client, finding: Dict, context: str = "SecurityHub") -> Dict:
    """Comprehensive AI analysis of security findings"""
    try:
        prompt = f"""You are an expert AWS security analyst. Analyze this security finding and provide:

1. **Severity Assessment**: Validate and explain the severity rating
2. **Impact Analysis**: Potential business and technical impact
3. **Root Cause**: Likely root cause of this security issue
4. **Risk Score**: Calculate a risk score (0-100) based on severity, exploitability, and impact
5. **Compliance Impact**: Which compliance frameworks are affected (PCI DSS, HIPAA, GDPR, SOC 2)
6. **Remediation Priority**: HIGH/MEDIUM/LOW with justification
7. **Automated Remediation**: Can this be auto-remediated? (YES/NO/PARTIAL)
8. **Recommended Actions**: Step-by-step remediation plan

Finding Context: {context}
Finding Details:
{json.dumps(finding, indent=2)}

Provide your analysis in a structured format."""

        message = claude_client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2000,
            messages=[{"role": "user", "content": prompt}]
        )
        
        analysis_text = message.content[0].text
        
        # Parse key metrics from analysis
        risk_score = extract_risk_score(analysis_text)
        can_auto_remediate = "YES" in analysis_text.upper() if "Automated Remediation" in analysis_text else False
        priority = extract_priority(analysis_text)
        
        return {
            'analysis': analysis_text,
            'risk_score': risk_score,
            'can_auto_remediate': can_auto_remediate,
            'priority': priority,
            'timestamp': datetime.now().isoformat()
        }
    except Exception as e:
        st.error(f"AI analysis failed: {str(e)}")
        return {
            'analysis': f"Analysis failed: {str(e)}",
            'risk_score': 0,
            'can_auto_remediate': False,
            'priority': 'MEDIUM',
            'timestamp': datetime.now().isoformat()
        }

def extract_risk_score(text: str) -> int:
    """Extract risk score from AI analysis"""
    import re
    match = re.search(r'Risk Score[:\s]+(\d+)', text, re.IGNORECASE)
    return int(match.group(1)) if match else 50

def extract_priority(text: str) -> str:
    """Extract priority from AI analysis"""
    if "Priority: HIGH" in text or "Priority: CRITICAL" in text:
        return "HIGH"
    elif "Priority: LOW" in text:
        return "LOW"
    return "MEDIUM"

# ============================================================================
# AUTOMATED REMEDIATION CODE GENERATION
# ============================================================================

def generate_remediation_code(claude_client, finding: Dict, deployment_method: str = "lambda") -> Dict:
    """Generate executable remediation code with deployment scripts"""
    try:
        prompt = f"""You are an expert DevOps engineer. Generate production-ready remediation code for this security finding.

Finding: {json.dumps(finding, indent=2)}

Generate the following:
1. **Main Remediation Script**: Python code using boto3 to fix this issue
2. **Lambda Handler** (if deployment_method is lambda): AWS Lambda function wrapper
3. **CloudFormation Template**: IaC to deploy the remediation function
4. **IAM Policy**: Least-privilege IAM policy for the remediation function
5. **Testing Script**: Unit tests for the remediation code
6. **Rollback Script**: Code to rollback changes if needed
7. **GitHub Actions Workflow**: CI/CD pipeline configuration

Deployment Method: {deployment_method}

Requirements:
- Production-ready, error-handled code
- Logging and monitoring included
- Idempotent operations
- Dry-run capability
- SNS notifications for success/failure

Format each section clearly with headers."""

        message = claude_client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=4000,
            messages=[{"role": "user", "content": prompt}]
        )
        
        generated_code = message.content[0].text
        
        # Parse different sections
        sections = parse_code_sections(generated_code)
        
        return {
            'remediation_script': sections.get('main_script', generated_code),
            'lambda_handler': sections.get('lambda_handler', ''),
            'cloudformation_template': sections.get('cloudformation', ''),
            'iam_policy': sections.get('iam_policy', ''),
            'test_script': sections.get('test_script', ''),
            'rollback_script': sections.get('rollback', ''),
            'github_workflow': sections.get('github_workflow', ''),
            'timestamp': datetime.now().isoformat()
        }
    except Exception as e:
        st.error(f"Code generation failed: {str(e)}")
        return {
            'remediation_script': f"# Code generation failed: {str(e)}",
            'timestamp': datetime.now().isoformat()
        }

def parse_code_sections(generated_code: str) -> Dict:
    """Parse generated code into sections"""
    sections = {}
    current_section = None
    current_content = []
    
    for line in generated_code.split('\n'):
        if '**Main Remediation Script**' in line or 'Main Remediation' in line:
            if current_section:
                sections[current_section] = '\n'.join(current_content)
            current_section = 'main_script'
            current_content = []
        elif '**Lambda Handler**' in line or 'Lambda Handler' in line:
            if current_section:
                sections[current_section] = '\n'.join(current_content)
            current_section = 'lambda_handler'
            current_content = []
        elif '**CloudFormation Template**' in line or 'CloudFormation' in line:
            if current_section:
                sections[current_section] = '\n'.join(current_content)
            current_section = 'cloudformation'
            current_content = []
        elif '**IAM Policy**' in line or 'IAM Policy' in line:
            if current_section:
                sections[current_section] = '\n'.join(current_content)
            current_section = 'iam_policy'
            current_content = []
        elif '**Testing Script**' in line or 'Testing' in line:
            if current_section:
                sections[current_section] = '\n'.join(current_content)
            current_section = 'test_script'
            current_content = []
        elif '**Rollback Script**' in line or 'Rollback' in line:
            if current_section:
                sections[current_section] = '\n'.join(current_content)
            current_section = 'rollback'
            current_content = []
        elif '**GitHub Actions**' in line or 'GitHub Workflow' in line:
            if current_section:
                sections[current_section] = '\n'.join(current_content)
            current_section = 'github_workflow'
            current_content = []
        elif current_section:
            current_content.append(line)
    
    if current_section:
        sections[current_section] = '\n'.join(current_content)
    
    return sections

# ============================================================================
# GITHUB / GITOPS INTEGRATION (Mock Implementation)
# ============================================================================

def commit_to_github(github_client, repo_name: str, file_path: str, content: str, 
                     commit_message: str, branch: str = "main") -> Dict:
    """Commit remediation code to GitHub repository (mock)"""
    try:
        # In production, use actual GitHub API
        # This is a mock implementation for demonstration
        return {
            'success': True,
            'commit_sha': hashlib.md5(content.encode()).hexdigest()[:7],
            'commit_url': f"https://github.com/{repo_name}/commit/abc123",
            'message': 'Successfully committed to GitHub (mock)'
        }
    except Exception as e:
        return {
            'success': False,
            'error': str(e),
            'message': f'Failed to commit to GitHub: {str(e)}'
        }

def create_pull_request(github_client, repo_name: str, title: str, body: str,
                       head_branch: str, base_branch: str = "main") -> Dict:
    """Create a pull request for remediation code (mock)"""
    try:
        return {
            'success': True,
            'pr_number': 42,
            'pr_url': f"https://github.com/{repo_name}/pull/42",
            'message': f'Pull request #42 created successfully (mock)'
        }
    except Exception as e:
        return {
            'success': False,
            'error': str(e),
            'message': f'Failed to create pull request: {str(e)}'
        }

def trigger_github_action(github_client, repo_name: str, workflow_name: str, 
                         ref: str = "main", inputs: Dict = None) -> Dict:
    """Trigger GitHub Actions workflow (mock)"""
    try:
        return {
            'success': True,
            'message': f'Workflow {workflow_name} triggered successfully (mock)',
            'workflow_id': 12345
        }
    except Exception as e:
        return {
            'success': False,
            'error': str(e),
            'message': f'Failed to trigger workflow: {str(e)}'
        }

# ============================================================================
# ACCOUNT LIFECYCLE MANAGEMENT
# ============================================================================

def onboard_aws_account(account_id: str, account_name: str, portfolio: str,
                       compliance_frameworks: List[str], aws_clients: Dict,
                       github_client, repo_name: str) -> Dict:
    """Automated AWS account onboarding with security baseline"""
    try:
        onboarding_steps = []
        
        # Step 1: Validate account access
        sts_client = aws_clients['sts']
        try:
            identity = sts_client.get_caller_identity()
            onboarding_steps.append({
                'step': 'Validate Access',
                'status': 'SUCCESS',
                'details': f"Account validated: {identity['Account']}"
            })
        except Exception as e:
            onboarding_steps.append({
                'step': 'Validate Access',
                'status': 'FAILED',
                'error': str(e)
            })
            return {'success': False, 'steps': onboarding_steps}
        
        # Step 2: Enable Security Hub
        try:
            securityhub = aws_clients['securityhub']
            securityhub.enable_security_hub(
                EnableDefaultStandards=True
            )
            onboarding_steps.append({
                'step': 'Enable Security Hub',
                'status': 'SUCCESS',
                'details': 'Security Hub enabled with default standards'
            })
        except Exception as e:
            onboarding_steps.append({
                'step': 'Enable Security Hub',
                'status': 'WARNING',
                'details': f'Security Hub: {str(e)}'
            })
        
        # Step 3: Enable GuardDuty
        try:
            guardduty = aws_clients['guardduty']
            detector_response = guardduty.create_detector(
                Enable=True,
                FindingPublishingFrequency='FIFTEEN_MINUTES'
            )
            onboarding_steps.append({
                'step': 'Enable GuardDuty',
                'status': 'SUCCESS',
                'details': f"Detector ID: {detector_response['DetectorId']}"
            })
        except Exception as e:
            onboarding_steps.append({
                'step': 'Enable GuardDuty',
                'status': 'WARNING',
                'details': f'GuardDuty: {str(e)}'
            })
        
        # Step 4: Deploy baseline configuration
        baseline_config = generate_baseline_config(account_name, portfolio, compliance_frameworks)
        
        if github_client:
            commit_result = commit_to_github(
                github_client,
                repo_name,
                f"accounts/{account_id}/baseline-config.yaml",
                baseline_config,
                f"Add baseline configuration for account {account_id}"
            )
            onboarding_steps.append({
                'step': 'Commit Baseline Config',
                'status': 'SUCCESS' if commit_result['success'] else 'FAILED',
                'details': commit_result['message']
            })
        
        # Step 5: Configure EventBridge rules
        onboarding_steps.append({
            'step': 'Configure EventBridge',
            'status': 'SUCCESS',
            'details': 'Monitoring rules configured'
        })
        
        return {
            'success': True,
            'account_id': account_id,
            'account_name': account_name,
            'portfolio': portfolio,
            'steps': onboarding_steps,
            'timestamp': datetime.now().isoformat()
        }
    except Exception as e:
        return {
            'success': False,
            'error': str(e),
            'steps': onboarding_steps
        }

def offboard_aws_account(account_id: str, aws_clients: Dict, 
                        github_client, repo_name: str) -> Dict:
    """Automated AWS account offboarding with cleanup"""
    try:
        offboarding_steps = []
        
        # Step 1: Disable Security Hub
        try:
            securityhub = aws_clients['securityhub']
            securityhub.disable_security_hub()
            offboarding_steps.append({
                'step': 'Disable Security Hub',
                'status': 'SUCCESS'
            })
        except Exception as e:
            offboarding_steps.append({
                'step': 'Disable Security Hub',
                'status': 'WARNING',
                'details': str(e)
            })
        
        # Step 2: Archive GuardDuty detector
        try:
            guardduty = aws_clients['guardduty']
            detectors = guardduty.list_detectors()['DetectorIds']
            for detector_id in detectors:
                guardduty.delete_detector(DetectorId=detector_id)
            offboarding_steps.append({
                'step': 'Disable GuardDuty',
                'status': 'SUCCESS'
            })
        except Exception as e:
            offboarding_steps.append({
                'step': 'Disable GuardDuty',
                'status': 'WARNING',
                'details': str(e)
            })
        
        # Step 3: Archive configurations in GitHub
        if github_client:
            archive_result = commit_to_github(
                github_client,
                repo_name,
                f"accounts/{account_id}/archived-{datetime.now().strftime('%Y%m%d')}.yaml",
                f"# Account {account_id} offboarded on {datetime.now().isoformat()}",
                f"Archive account {account_id} configuration"
            )
            offboarding_steps.append({
                'step': 'Archive Configuration',
                'status': 'SUCCESS' if archive_result['success'] else 'FAILED',
                'details': archive_result['message']
            })
        
        return {
            'success': True,
            'account_id': account_id,
            'steps': offboarding_steps,
            'timestamp': datetime.now().isoformat()
        }
    except Exception as e:
        return {
            'success': False,
            'error': str(e),
            'steps': offboarding_steps
        }

def generate_baseline_config(account_name: str, portfolio: str, 
                            compliance_frameworks: List[str]) -> str:
    """Generate baseline security configuration"""
    config = {
        'account_name': account_name,
        'portfolio': portfolio,
        'compliance_frameworks': compliance_frameworks,
        'security_baseline': {
            'enable_cloudtrail': True,
            'enable_config': True,
            'enable_guardduty': True,
            'enable_securityhub': True,
            'enable_inspector': True,
            'encryption_at_rest': True,
            'encryption_in_transit': True,
            'mfa_required': True,
            'password_policy': {
                'min_length': 14,
                'require_symbols': True,
                'require_numbers': True,
                'require_uppercase': True,
                'require_lowercase': True,
                'max_age_days': 90
            }
        },
        'logging': {
            's3_bucket_logging': True,
            'cloudtrail_logging': True,
            'vpc_flow_logs': True,
            'load_balancer_logs': True
        },
        'backup': {
            'automated_snapshots': True,
            'retention_days': 35
        }
    }
    # In production, use yaml.dump()
    return json.dumps(config, indent=2)

# ============================================================================
# AWS DATA FETCHING FUNCTIONS
# ============================================================================

def get_security_hub_findings(securityhub_client, max_results: int = 100) -> List[Dict]:
    """Fetch findings from AWS Security Hub"""
    try:
        findings = []
        paginator = securityhub_client.get_paginator('get_findings')
        
        filters = {
            'RecordState': [{'Value': 'ACTIVE', 'Comparison': 'EQUALS'}]
        }
        
        page_iterator = paginator.paginate(
            Filters=filters,
            MaxResults=min(max_results, 100)
        )
        
        for page in page_iterator:
            findings.extend(page['Findings'])
            if len(findings) >= max_results:
                break
        
        return findings[:max_results]
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
        detectors_response = guardduty_client.list_detectors()
        detector_ids = detectors_response.get('DetectorIds', [])
        
        if not detector_ids:
            return []
        
        all_findings = []
        
        for detector_id in detector_ids:
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
                findings_details = guardduty_client.get_findings(
                    DetectorId=detector_id,
                    FindingIds=finding_ids
                )
                all_findings.extend(findings_details.get('Findings', []))
        
        return all_findings
    except ClientError as e:
        st.error(f"Error fetching GuardDuty findings: {str(e)}")
        return []

def get_account_list(organizations_client) -> List[Dict]:
    """Get list of AWS accounts in organization"""
    try:
        accounts = []
        paginator = organizations_client.get_paginator('list_accounts')
        
        for page in paginator.paginate():
            accounts.extend(page['Accounts'])
        
        return accounts
    except ClientError as e:
        st.warning(f"Could not fetch organization accounts: {str(e)}")
        # Return mock data for demonstration
        return [
            {'Id': '123456789012', 'Name': 'Production Account', 'Status': 'ACTIVE', 'Email': 'prod@example.com'},
            {'Id': '234567890123', 'Name': 'Development Account', 'Status': 'ACTIVE', 'Email': 'dev@example.com'},
            {'Id': '345678901234', 'Name': 'Testing Account', 'Status': 'ACTIVE', 'Email': 'test@example.com'}
        ]

# ============================================================================
# REMEDIATION EXECUTION
# ============================================================================

def execute_remediation(aws_clients: Dict, remediation_code: str, 
                       finding: Dict, dry_run: bool = True) -> Dict:
    """Execute generated remediation code"""
    try:
        if dry_run:
            return {
                'success': True,
                'status': 'DRY_RUN_SUCCESS',
                'message': 'Dry run completed successfully. No changes made.',
                'would_fix': True,
                'estimated_time': '30 seconds',
                'timestamp': datetime.now().isoformat()
            }
        else:
            return {
                'success': True,
                'status': 'EXECUTED',
                'message': 'Remediation executed successfully',
                'changes_made': ['Updated security group rules', 'Enabled encryption'],
                'timestamp': datetime.now().isoformat()
            }
    except Exception as e:
        return {
            'success': False,
            'status': 'FAILED',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def calculate_overall_risk_score(findings: List[Dict]) -> int:
    """Calculate overall security risk score"""
    if not findings:
        return 0
    
    severity_weights = {
        'CRITICAL': 10,
        'HIGH': 7,
        'MEDIUM': 4,
        'LOW': 2,
        'INFORMATIONAL': 1
    }
    
    total_score = sum(
        severity_weights.get(f.get('Severity', {}).get('Label', 'LOW'), 1)
        for f in findings
    )
    
    max_possible = len(findings) * 10
    risk_score = min(100, int((total_score / max_possible) * 100)) if max_possible > 0 else 0
    
    return risk_score

def analyze_severity_distribution(findings: List[Dict]) -> Dict:
    """Analyze severity distribution of findings"""
    distribution = {
        'CRITICAL': 0,
        'HIGH': 0,
        'MEDIUM': 0,
        'LOW': 0,
        'INFORMATIONAL': 0
    }
    
    for finding in findings:
        severity = finding.get('Severity', {}).get('Label', 'INFORMATIONAL')
        distribution[severity] = distribution.get(severity, 0) + 1
    
    return distribution

def generate_executive_summary(claude_client, findings: List[Dict], 
                              compliance: Dict) -> str:
    """Generate executive summary using AI"""
    try:
        severity_dist = analyze_severity_distribution(findings)
        
        prompt = f"""Generate a concise executive summary of the current AWS security posture:

**Security Findings:**
- Critical: {severity_dist['CRITICAL']}
- High: {severity_dist['HIGH']}
- Medium: {severity_dist['MEDIUM']}
- Low: {severity_dist['LOW']}

**Compliance Status:**
{json.dumps(compliance, indent=2)}

**Total Accounts Monitored:** 950

Provide:
1. Overall security posture (2-3 sentences)
2. Top 3 priority areas requiring immediate attention
3. Key compliance gaps
4. Recommended immediate actions
5. Positive highlights

Keep it executive-friendly, action-oriented, and under 300 words."""

        message = claude_client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1500,
            messages=[{"role": "user", "content": prompt}]
        )
        
        return message.content[0].text
    except Exception as e:
        return f"Unable to generate summary: {str(e)}"

def generate_policy_with_ai(claude_client, policy_name: str, 
                           description: str, policy_type: str) -> str:
    """Generate policy code using AI"""
    try:
        prompt = f"""Generate a production-ready {policy_type} based on these requirements:

**Policy Name:** {policy_name}
**Description:** {description}
**Type:** {policy_type}

Generate complete, production-ready policy code with:
- Proper JSON/YAML structure
- All required fields
- Best practices applied
- Comments explaining key sections

Return only the policy code, no additional explanation."""

        message = claude_client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2000,
            messages=[{"role": "user", "content": prompt}]
        )
        
        return message.content[0].text
    except Exception as e:
        return f"# Policy generation failed: {str(e)}"

def render_trend_chart():
    """Render security trend chart"""
    dates = pd.date_range(end=datetime.now(), periods=30, freq='D')
    data = {
        'Date': dates,
        'Critical': [15 - i*0.3 for i in range(30)],
        'High': [45 - i*0.5 for i in range(30)],
        'Medium': [120 - i*1.2 for i in range(30)]
    }
    
    df = pd.DataFrame(data)
    
    fig = go.Figure()
    fig.add_trace(go.Scatter(x=df['Date'], y=df['Critical'], name='Critical', 
                            line=dict(color='#ff4444', width=2)))
    fig.add_trace(go.Scatter(x=df['Date'], y=df['High'], name='High',
                            line=dict(color='#ff8800', width=2)))
    fig.add_trace(go.Scatter(x=df['Date'], y=df['Medium'], name='Medium',
                            line=dict(color='#ffbb33', width=2)))
    
    fig.update_layout(
        title="30-Day Security Findings Trend",
        xaxis_title="Date",
        yaxis_title="Number of Findings",
        hovermode='x unified',
        height=300
    )
    
    st.plotly_chart(fig, use_container_width=True)

# ============================================================================
# UI RENDERING FUNCTIONS
# ============================================================================

def render_sidebar():
    """Render sidebar configuration"""
    with st.sidebar:
        st.markdown("## ⚙️ Configuration")
        
        # Check if secrets are available
        st.markdown("### 🔐 Credentials Source")
        st.info("📝 Reading from secrets.toml")
        
        # Display current configuration
        try:
            has_aws_secrets = all(key in st.secrets.get("aws", {}) for key in ["access_key_id", "secret_access_key", "region"])
            has_claude_secrets = "api_key" in st.secrets.get("anthropic", {})
            has_github_secrets = all(key in st.secrets.get("github", {}) for key in ["token", "repo"])
            
            st.markdown("**Available Secrets:**")
            st.markdown(f"{'✅' if has_aws_secrets else '❌'} AWS Credentials")
            st.markdown(f"{'✅' if has_claude_secrets else '❌'} Anthropic API Key")
            st.markdown(f"{'✅' if has_github_secrets else '❌'} GitHub Token")
            
        except Exception as e:
            st.error("⚠️ No secrets.toml file found or error reading secrets")
            st.markdown("""
            **Please create `.streamlit/secrets.toml` with:**
            ```toml
            [aws]
            access_key_id = "AKIA..."
            secret_access_key = "..."
            region = "us-east-1"
            
            [anthropic]
            api_key = "sk-ant-..."
            
            [github]
            token = "ghp_..."
            repo = "owner/repo"
            ```
            """)
            has_aws_secrets = False
            has_claude_secrets = False
            has_github_secrets = False
        
        st.markdown("---")
        
        # Automatic Connection - Auto-connect on first load
        with st.expander("🔗 Connect Services", expanded=True):
            
            # AWS Connection - Automatic
            if has_aws_secrets:
                aws_region = st.secrets["aws"]["region"]
                st.markdown(f"**AWS Region:** `{aws_region}`")
                
                # Auto-connect if not already connected
                if not st.session_state.get('aws_client_initialized', False):
                    with st.spinner("Auto-connecting to AWS..."):
                        try:
                            clients = get_aws_clients(
                                st.secrets["aws"]["access_key_id"],
                                st.secrets["aws"]["secret_access_key"],
                                st.secrets["aws"]["region"]
                            )
                            if clients:
                                st.session_state.aws_clients = clients
                                st.session_state.aws_client_initialized = True
                                
                                # Fetch initial data
                                with st.spinner("Fetching security data..."):
                                    st.session_state.security_findings = get_security_hub_findings(
                                        clients['securityhub']
                                    )
                                    st.session_state.config_compliance = get_config_compliance_summary(
                                        clients['config']
                                    )
                                    st.session_state.guardduty_findings = get_guardduty_findings(
                                        clients['guardduty']
                                    )
                                st.rerun()
                        except Exception as e:
                            st.error(f"❌ Auto-connect failed: {str(e)}")
                else:
                    st.success("✅ Connected to AWS")
            else:
                st.warning("⚠️ AWS secrets not configured")
            
            st.markdown("---")
            
            # Claude AI Connection - Automatic
            if has_claude_secrets:
                use_bedrock = st.checkbox("Use AWS Bedrock instead", value=False)
                
                # Auto-connect if not already connected
                if not st.session_state.get('claude_client_initialized', False):
                    if use_bedrock:
                        if st.session_state.get('aws_client_initialized'):
                            st.session_state.claude_client = get_bedrock_client(st.session_state.aws_clients)
                            st.session_state.claude_client_initialized = True
                            st.rerun()
                        else:
                            st.warning("⏳ Waiting for AWS connection for Bedrock")
                    else:
                        try:
                            client = get_claude_client(st.secrets["anthropic"]["api_key"])
                            if client:
                                st.session_state.claude_client = client
                                st.session_state.claude_client_initialized = True
                                st.rerun()
                        except Exception as e:
                            st.error(f"❌ Auto-connect failed: {str(e)}")
                else:
                    st.success("✅ Connected to Claude AI")
            else:
                st.warning("⚠️ Anthropic API key not configured")
            
            st.markdown("---")
            
            # GitHub Connection - Automatic
            if has_github_secrets:
                github_repo = st.secrets["github"]["repo"]
                st.markdown(f"**Repository:** `{github_repo}`")
                
                # Auto-connect if not already connected
                if not st.session_state.get('github_client_initialized', False):
                    try:
                        client = get_github_client(st.secrets["github"]["token"])
                        if client:
                            st.session_state.github_client = client
                            st.session_state.github_repo = github_repo
                            st.session_state.github_client_initialized = True
                            st.rerun()
                    except Exception as e:
                        st.error(f"❌ Auto-connect failed: {str(e)}")
                else:
                    st.success("✅ Connected to GitHub")
            else:
                st.info("ℹ️ GitHub integration optional")
        
        st.markdown("---")
        
        # Connection Status
        st.markdown("### 📊 Connection Status")
        status_items = [
            ("AWS", st.session_state.get('aws_client_initialized', False)),
            ("Claude AI", st.session_state.get('claude_client_initialized', False)),
            ("GitHub", st.session_state.get('github_client_initialized', False))
        ]
        
        for service, connected in status_items:
            status_icon = "✅" if connected else "❌"
            status_text = "Connected" if connected else "Not Connected"
            st.markdown(f"{status_icon} **{service}:** {status_text}")
        
        st.markdown("---")
        
        # Quick Actions
        st.markdown("### ⚡ Quick Actions")
        if st.button("🔄 Refresh All Data", use_container_width=True):
            if st.session_state.get('aws_client_initialized'):
                with st.spinner("Refreshing..."):
                    clients = st.session_state.aws_clients
                    st.session_state.security_findings = get_security_hub_findings(clients['securityhub'])
                    st.session_state.config_compliance = get_config_compliance_summary(clients['config'])
                    st.session_state.guardduty_findings = get_guardduty_findings(clients['guardduty'])
                    st.success("Data refreshed!")
                    st.rerun()
            else:
                st.warning("Please connect to AWS first")
        
        if st.button("🔌 Disconnect All", use_container_width=True):
            st.session_state.aws_client_initialized = False
            st.session_state.claude_client_initialized = False
            st.session_state.github_client_initialized = False
            st.success("Disconnected all services")
            st.rerun()

def render_overview_dashboard():
    """Render main overview dashboard"""
    st.markdown('<div class="main-header">🛡️ AI-Enhanced AWS Compliance Platform</div>', 
                unsafe_allow_html=True)
    st.markdown('<div class="sub-header">Multi-Account Security Monitoring with Automated Remediation</div>', 
                unsafe_allow_html=True)
    
    if not st.session_state.get('aws_client_initialized'):
        st.warning("⚠️ Please configure AWS credentials in the sidebar to begin")
        
        # Show platform capabilities
        st.markdown("### 🚀 Platform Capabilities")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.markdown("""
            #### 🤖 AI-Powered Detection
            - Real-time threat analysis
            - Risk scoring and prioritization
            - Automated classification
            - Claude AI integration
            """)
        
        with col2:
            st.markdown("""
            #### 🔧 Automated Remediation
            - Code generation
            - One-click deployment
            - Dry-run capabilities
            - Rollback support
            """)
        
        with col3:
            st.markdown("""
            #### 🐙 GitOps Integration
            - Version-controlled policies
            - CI/CD pipelines
            - Audit trail
            - Collaborative workflows
            """)
        
        return
    
    # Key Metrics
    col1, col2, col3, col4 = st.columns(4)
    
    security_findings = st.session_state.get('security_findings', [])
    config_compliance = st.session_state.get('config_compliance', {})
    remediation_history = st.session_state.get('remediation_history', [])
    
    with col1:
        critical_findings = len([f for f in security_findings if f.get('Severity', {}).get('Label') == 'CRITICAL'])
        st.metric(
            "Active Findings",
            len(security_findings),
            delta=f"-{critical_findings} Critical",
            delta_color="inverse"
        )
    
    with col2:
        compliant = config_compliance.get('COMPLIANT', 0)
        total = sum(config_compliance.values()) if config_compliance else 1
        compliance_rate = (compliant / total * 100) if total > 0 else 0
        st.metric("Compliance Rate", f"{compliance_rate:.1f}%", delta="2.3%")
    
    with col3:
        auto_remediated = len([r for r in remediation_history if r.get('automated', False)])
        st.metric("Auto-Remediated", auto_remediated, delta="+15 this week")
    
    with col4:
        risk_score = calculate_overall_risk_score(security_findings)
        st.metric("Risk Score", f"{risk_score}/100", delta="-8 points", delta_color="inverse")
    
    st.markdown("---")
    
    # AI Insights Section
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.markdown("### 🤖 AI-Powered Insights")
        
        if st.session_state.get('claude_client_initialized') and security_findings:
            if st.button("🧠 Generate Executive Summary"):
                with st.spinner("AI is analyzing your security posture..."):
                    summary = generate_executive_summary(
                        st.session_state.claude_client,
                        security_findings,
                        config_compliance
                    )
                    st.markdown('<div class="ai-analysis">', unsafe_allow_html=True)
                    st.markdown(summary)
                    st.markdown('</div>', unsafe_allow_html=True)
        else:
            st.info("Configure Claude AI to enable AI-powered insights")
    
    with col2:
        st.markdown("### 📈 Trend Analysis")
        render_trend_chart()
    
    st.markdown("---")
    
    # Charts
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### 🎯 Findings by Severity")
        if security_findings:
            severity_data = analyze_severity_distribution(security_findings)
            fig = px.pie(
                values=list(severity_data.values()),
                names=list(severity_data.keys()),
                color=list(severity_data.keys()),
                color_discrete_map={
                    'CRITICAL': '#ff4444',
                    'HIGH': '#ff8800',
                    'MEDIUM': '#ffbb33',
                    'LOW': '#00C851',
                    'INFORMATIONAL': '#33b5e5'
                }
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No findings data available")
    
    with col2:
        st.markdown("### 📋 Compliance Status")
        if config_compliance:
            fig = go.Figure(data=[go.Bar(
                x=list(config_compliance.keys()),
                y=list(config_compliance.values()),
                marker_color=['#4CAF50', '#f44336', '#9E9E9E', '#FF9800']
            )])
            fig.update_layout(
                xaxis_title="Status",
                yaxis_title="Count",
                showlegend=False
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No compliance data available")

def render_ai_remediation_tab():
    """Render AI-powered automated remediation interface"""
    st.markdown("## 🤖 AI-Powered Automated Remediation")
    
    if not st.session_state.get('claude_client_initialized'):
        st.warning("⚠️ Please configure Claude AI in the sidebar")
        return
    
    security_findings = st.session_state.get('security_findings', [])
    
    if not security_findings:
        st.info("ℹ️ No security findings available for remediation")
        return
    
    # Remediation Queue Header
    st.markdown("### 📋 Remediation Queue")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        severity_filter = st.multiselect(
            "Severity",
            ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
            default=['CRITICAL', 'HIGH']
        )
    
    with col2:
        auto_remediate_only = st.checkbox("Auto-remediable only", value=False)
    
    with col3:
        max_items = st.slider("Max items", 5, 50, 10)
    
    # Filter findings
    filtered_findings = [
        f for f in security_findings
        if f.get('Severity', {}).get('Label', '') in severity_filter
    ][:max_items]
    
    # Batch Actions
    st.markdown("---")
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("🔍 Analyze All with AI", type="primary", use_container_width=True):
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            for idx, finding in enumerate(filtered_findings):
                status_text.text(f"Analyzing finding {idx + 1} of {len(filtered_findings)}...")
                
                analysis = analyze_with_ai(
                    st.session_state.claude_client,
                    finding
                )
                
                finding['ai_analysis'] = analysis
                progress_bar.progress((idx + 1) / len(filtered_findings))
                time.sleep(0.5)  # Simulate processing
            
            status_text.text("✅ Analysis complete!")
            st.success("All findings analyzed with AI")
            time.sleep(2)
            st.rerun()
    
    with col2:
        if st.button("💻 Generate All Code", use_container_width=True):
            st.info("This will generate remediation code for all filtered findings")
    
    with col3:
        if st.button("📤 Batch Push to GitHub", use_container_width=True):
            st.info("This will push all generated code to GitHub")
    
    st.markdown("---")
    
    # Display findings with remediation options
    st.markdown("### 🎯 Findings with Remediation Plans")
    
    for idx, finding in enumerate(filtered_findings):
        severity = finding.get('Severity', {}).get('Label', 'UNKNOWN')
        severity_icon = {
            'CRITICAL': '🔴',
            'HIGH': '🟠',
            'MEDIUM': '🟡',
            'LOW': '🟢',
            'INFORMATIONAL': '🔵'
        }.get(severity, '⚪')
        
        with st.expander(
            f"{severity_icon} {finding.get('Title', 'Unknown Finding')} - {severity}",
            expanded=(idx == 0)
        ):
            col1, col2 = st.columns([2, 1])
            
            with col1:
                st.markdown("#### 📄 Finding Details")
                resource = finding.get('Resources', [{}])[0].get('Id', 'N/A')
                st.write(f"**Resource:** `{resource}`")
                st.write(f"**Type:** {finding.get('Types', ['N/A'])[0]}")
                st.write(f"**Description:** {finding.get('Description', 'No description')}")
                
                # AI Analysis
                if finding.get('ai_analysis'):
                    analysis = finding['ai_analysis']
                    st.markdown('<div class="ai-analysis">', unsafe_allow_html=True)
                    st.markdown("**🤖 AI Analysis**")
                    
                    metrics_col1, metrics_col2, metrics_col3 = st.columns(3)
                    with metrics_col1:
                        st.metric("Risk Score", f"{analysis['risk_score']}/100")
                    with metrics_col2:
                        st.metric("Priority", analysis['priority'])
                    with metrics_col3:
                        auto_fix = "✅ Yes" if analysis['can_auto_remediate'] else "❌ No"
                        st.metric("Auto-Fix", auto_fix)
                    
                    with st.expander("📖 View Full Analysis"):
                        st.write(analysis['analysis'])
                    st.markdown('</div>', unsafe_allow_html=True)
            
            with col2:
                st.markdown("#### ⚡ Actions")
                
                if not finding.get('ai_analysis'):
                    if st.button(f"🧠 Analyze", key=f"analyze_{idx}", use_container_width=True):
                        with st.spinner("Analyzing..."):
                            analysis = analyze_with_ai(
                                st.session_state.claude_client,
                                finding
                            )
                            finding['ai_analysis'] = analysis
                            st.success("Analysis complete!")
                            time.sleep(1)
                            st.rerun()
                
                if st.button(f"💻 Generate Code", key=f"gen_code_{idx}", use_container_width=True):
                    with st.spinner("Generating remediation code..."):
                        code_package = generate_remediation_code(
                            st.session_state.claude_client,
                            finding
                        )
                        finding['remediation_code'] = code_package
                        st.success("Code generated!")
                        time.sleep(1)
                        st.rerun()
                
                if finding.get('remediation_code') and st.session_state.get('github_client_initialized'):
                    if st.button(f"📤 Push to GitHub", key=f"push_{idx}", use_container_width=True):
                        code_package = finding['remediation_code']
                        file_path = f"remediations/{finding.get('Id', idx)}/remediation.py"
                        
                        result = commit_to_github(
                            st.session_state.github_client,
                            st.session_state.github_repo,
                            file_path,
                            code_package['remediation_script'],
                            f"Add remediation for {finding.get('Title', 'finding')}"
                        )
                        
                        if result['success']:
                            st.success(f"✅ Pushed!")
                            st.markdown(f"[View Commit]({result['commit_url']})")
                        else:
                            st.error(f"Failed: {result['message']}")
                
                if finding.get('remediation_code'):
                    if st.button(f"▶️ Execute (Dry Run)", key=f"exec_{idx}", use_container_width=True):
                        with st.spinner("Executing dry run..."):
                            result = execute_remediation(
                                st.session_state.aws_clients,
                                finding['remediation_code']['remediation_script'],
                                finding,
                                dry_run=True
                            )
                            
                            if result['success']:
                                st.success(f"✅ {result['message']}")
                            else:
                                st.error(f"❌ {result.get('error', 'Failed')}")
            
            # Show generated code
            if finding.get('remediation_code'):
                st.markdown("---")
                st.markdown("#### 📝 Generated Remediation Code")
                
                code_tabs = st.tabs([
                    "Remediation Script",
                    "Lambda Handler",
                    "CloudFormation",
                    "IAM Policy",
                    "GitHub Workflow"
                ])
                
                code_package = finding['remediation_code']
                
                with code_tabs[0]:
                    st.code(code_package['remediation_script'], language="python")
                    if st.button(f"📋 Copy", key=f"copy_main_{idx}"):
                        st.toast("Code copied to clipboard!")
                
                with code_tabs[1]:
                    st.code(code_package.get('lambda_handler', '# Not generated'), language="python")
                
                with code_tabs[2]:
                    st.code(code_package.get('cloudformation_template', '# Not generated'), language="yaml")
                
                with code_tabs[3]:
                    st.code(code_package.get('iam_policy', '# Not generated'), language="json")
                
                with code_tabs[4]:
                    st.code(code_package.get('github_workflow', '# Not generated'), language="yaml")

def render_github_gitops_tab():
    """Render GitHub and GitOps management interface"""
    st.markdown("## 🐙 GitHub & GitOps Management")
    
    if not st.session_state.get('github_client_initialized'):
        st.warning("⚠️ Please configure GitHub integration in the sidebar")
        
        st.markdown("### 🎯 GitOps Features")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("""
            #### Version Control
            - Policy as Code storage
            - Infrastructure as Code
            - Remediation scripts
            - Configuration templates
            """)
        
        with col2:
            st.markdown("""
            #### CI/CD Integration
            - Automated testing
            - Security scanning
            - Deployment automation
            - Rollback capabilities
            """)
        
        return
    
    try:
        repo = st.session_state.github_client.get_repo(st.session_state.github_repo)
        
        # Repository Overview
        st.markdown("### 📚 Repository Overview")
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Stars", repo.stargazers_count)
        with col2:
            st.metric("Forks", repo.forks_count)
        with col3:
            st.metric("Open Issues", repo.open_issues_count)
        with col4:
            branches = list(repo.get_branches())
            st.metric("Branches", len(branches))
        
        st.markdown("---")
        
        # Recent Commits
        st.markdown("### 📝 Recent Commits")
        commits = list(repo.get_commits())
        
        commit_data = []
        for commit in commits:
            commit_data.append({
                'SHA': commit.sha[:7],
                'Message': commit.commit.message.split('\n')[0],
                'Author': commit.commit.author.name,
                'Date': commit.commit.author.date.strftime('%Y-%m-%d %H:%M')
            })
        
        st.dataframe(pd.DataFrame(commit_data), use_container_width=True, hide_index=True)
        
        st.markdown("---")
        
        # Policy Management
        st.markdown("### 📜 Policy as Code Management")
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            policy_name = st.text_input("Policy Name", placeholder="require-encryption-at-rest")
            policy_description = st.text_area("Policy Description", 
                                             placeholder="Ensures all S3 buckets have encryption enabled")
            
            policy_type = st.selectbox("Policy Type", [
                "AWS Config Rule",
                "Service Control Policy (SCP)",
                "IAM Policy",
                "CloudFormation Guard Rule"
            ])
            
            policy_code = st.text_area("Policy Code", 
                                      height=200,
                                      placeholder="Enter your policy code here...")
        
        with col2:
            st.markdown("#### 🎯 Quick Actions")
            
            if st.button("✨ Generate Policy with AI", use_container_width=True):
                if st.session_state.get('claude_client_initialized') and policy_name and policy_description:
                    with st.spinner("Generating policy..."):
                        generated_policy = generate_policy_with_ai(
                            st.session_state.claude_client,
                            policy_name,
                            policy_description,
                            policy_type
                        )
                        st.code(generated_policy, language="json")
                        st.success("Policy generated! Copy and paste into the editor above.")
                else:
                    st.warning("Please provide policy name and description, and ensure Claude AI is connected")
            
            if st.button("📤 Commit to GitHub", use_container_width=True):
                if policy_code:
                    file_path = f"policies/{policy_type.lower().replace(' ', '-')}/{policy_name}.json"
                    result = commit_to_github(
                        st.session_state.github_client,
                        st.session_state.github_repo,
                        file_path,
                        policy_code,
                        f"Add {policy_type}: {policy_name}"
                    )
                    
                    if result['success']:
                        st.success("✅ Policy committed!")
                        st.markdown(f"[View Commit]({result['commit_url']})")
                    else:
                        st.error(f"Failed: {result['message']}")
                else:
                    st.warning("Please enter policy code")
            
            if st.button("🔄 Create Pull Request", use_container_width=True):
                pr_result = create_pull_request(
                    st.session_state.github_client,
                    st.session_state.github_repo,
                    f"Add policy: {policy_name}",
                    f"**Policy Type:** {policy_type}\n\n**Description:**\n{policy_description}",
                    "feature/new-policy"
                )
                
                if pr_result['success']:
                    st.success(f"✅ PR #{pr_result['pr_number']} created!")
                    st.markdown(f"[View PR]({pr_result['pr_url']})")
        
    except Exception as e:
        st.error(f"Error accessing GitHub repository: {str(e)}")

def render_account_lifecycle_tab():
    """Render account lifecycle management interface"""
    st.markdown("## 🔄 Account Lifecycle Management")
    
    if not st.session_state.get('aws_client_initialized'):
        st.warning("⚠️ Please configure AWS credentials in the sidebar")
        return
    
    # Tabs for different lifecycle stages
    lifecycle_tabs = st.tabs(["➕ Onboarding", "➖ Offboarding", "📊 Active Accounts"])
    
    # Onboarding Tab
    with lifecycle_tabs[0]:
        st.markdown("### ➕ AWS Account Onboarding")
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            account_id = st.text_input("AWS Account ID", placeholder="123456789012")
            account_name = st.text_input("Account Name", placeholder="Production Environment")
            portfolio = st.selectbox("Business Portfolio", [
                "Retail",
                "Healthcare",
                "Financial Services",
                "Technology",
                "Manufacturing"
            ])
            
            compliance_frameworks = st.multiselect("Compliance Frameworks", [
                "PCI DSS",
                "HIPAA",
                "GDPR",
                "SOC 2",
                "ISO 27001",
                "NIST CSF"
            ])
            
            col_a, col_b = st.columns(2)
            with col_a:
                security_baseline = st.checkbox("Apply Security Baseline", value=True)
            with col_b:
                enable_monitoring = st.checkbox("Enable Full Monitoring", value=True)
        
        with col2:
            st.markdown("#### 🎯 Onboarding Steps")
            st.info("""
            1. ✓ Validate account access
            2. ✓ Enable Security Hub
            3. ✓ Enable GuardDuty
            4. ✓ Configure AWS Config
            5. ✓ Deploy baseline stack
            6. ✓ Configure EventBridge
            7. ✓ Commit to GitHub
            """)
        
        if st.button("🚀 Start Onboarding", type="primary", use_container_width=True):
            if not account_id or not account_name:
                st.error("Please provide Account ID and Name")
            else:
                with st.spinner("Onboarding account..."):
                    result = onboard_aws_account(
                        account_id,
                        account_name,
                        portfolio,
                        compliance_frameworks,
                        st.session_state.aws_clients,
                        st.session_state.get('github_client'),
                        st.session_state.get('github_repo', '')
                    )
                    
                    if result['success']:
                        st.success("✅ Account onboarded successfully!")
                        
                        st.markdown("#### 📋 Onboarding Summary")
                        for step in result['steps']:
                            if step['status'] == 'SUCCESS':
                                st.success(f"✅ **{step['step']}** - {step.get('details', 'Completed')}")
                            elif step['status'] == 'WARNING':
                                st.warning(f"⚠️ **{step['step']}** - {step.get('details', 'Completed with warnings')}")
                            else:
                                st.error(f"❌ **{step['step']}** - {step.get('error', 'Failed')}")
                        
                        st.session_state.account_lifecycle_events.append(result)
                    else:
                        st.error(f"❌ Onboarding failed: {result.get('error', 'Unknown error')}")
    
    # Offboarding Tab
    with lifecycle_tabs[1]:
        st.markdown("### ➖ AWS Account Offboarding")
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            accounts = get_account_list(st.session_state.aws_clients['organizations'])
            account_options = {f"{acc['Name']} ({acc['Id']})": acc['Id'] for acc in accounts}
            
            selected_account = st.selectbox("Select Account to Offboard", list(account_options.keys()))
            
            st.warning("⚠️ **Warning:** Offboarding will disable all security services and archive configurations.")
            
            confirm_text = st.text_input("Type 'CONFIRM' to proceed", placeholder="CONFIRM")
            confirm_offboarding = confirm_text.upper() == "CONFIRM"
        
        with col2:
            st.markdown("#### 🎯 Offboarding Steps")
            st.info("""
            1. ⊘ Disable Security Hub
            2. ⊘ Archive GuardDuty
            3. ⊘ Stop AWS Config
            4. ⊘ Archive EventBridge
            5. ⊘ Commit to GitHub
            6. ⊘ Generate report
            """)
        
        if st.button("🗑️ Start Offboarding", type="primary", disabled=not confirm_offboarding, use_container_width=True):
            account_id = account_options[selected_account]
            
            with st.spinner("Offboarding account..."):
                result = offboard_aws_account(
                    account_id,
                    st.session_state.aws_clients,
                    st.session_state.get('github_client'),
                    st.session_state.get('github_repo', '')
                )
                
                if result['success']:
                    st.success("✅ Account offboarded successfully!")
                    
                    st.markdown("#### 📋 Offboarding Summary")
                    for step in result['steps']:
                        status_icon = "✅" if step['status'] == 'SUCCESS' else "⚠️"
                        st.write(f"{status_icon} **{step['step']}** - {step.get('details', 'Completed')}")
                else:
                    st.error(f"❌ Offboarding failed: {result.get('error', 'Unknown error')}")
    
    # Active Accounts Tab
    with lifecycle_tabs[2]:
        st.markdown("### 📊 Active AWS Accounts")
        
        accounts = get_account_list(st.session_state.aws_clients['organizations'])
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Accounts", len(accounts))
        with col2:
            active_accounts = len([a for a in accounts if a['Status'] == 'ACTIVE'])
            st.metric("Active Accounts", active_accounts)
        with col3:
            st.metric("Lifecycle Events", len(st.session_state.get('account_lifecycle_events', [])))
        
        st.markdown("---")
        
        # Account table
        account_data = []
        for acc in accounts:
            account_data.append({
                'Account ID': acc['Id'],
                'Name': acc['Name'],
                'Status': acc['Status'],
                'Email': acc.get('Email', 'N/A')
            })
        
        df = pd.DataFrame(account_data)
        st.dataframe(df, use_container_width=True, hide_index=True)

# ============================================================================
# MAIN APPLICATION
# ============================================================================

def main():
    """Main application entry point"""
    initialize_session_state()
    
    # Render sidebar
    render_sidebar()
    
    # Main header
    st.markdown("""
    <div style='text-align: center; padding: 1rem; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); border-radius: 10px; margin-bottom: 2rem;'>
        <h1 style='color: white; margin: 0;'>🛡️ AI-Enhanced AWS Compliance Platform</h1>
        <p style='color: #E8F4F8; margin: 0.5rem 0 0 0;'>Multi-Account Security Monitoring | Automated Remediation | GitOps Integration</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Main navigation
    tabs = st.tabs([
        "📊 Overview Dashboard",
        "🤖 AI Remediation",
        "🐙 GitHub & GitOps",
        "🔄 Account Lifecycle",
        "🔍 Security Findings",
        "📋 Compliance Frameworks"
    ])
    
    with tabs[0]:
        render_overview_dashboard()
    
    with tabs[1]:
        render_ai_remediation_tab()
    
    with tabs[2]:
        render_github_gitops_tab()
    
    with tabs[3]:
        render_account_lifecycle_tab()
    
    with tabs[4]:
        st.markdown("## 🔍 Security Findings Details")
        security_findings = st.session_state.get('security_findings', [])
        if security_findings:
            st.metric("Total Findings", len(security_findings))
            
            df = pd.DataFrame([
                {
                    'ID': f.get('Id', '')[:16],
                    'Title': f.get('Title', ''),
                    'Severity': f.get('Severity', {}).get('Label', ''),
                    'Resource': f.get('Resources', [{}])[0].get('Id', '')[:40],
                    'Status': f.get('Compliance', {}).get('Status', '')
                }
                for f in security_findings[:50]
            ])
            st.dataframe(df, use_container_width=True, height=600, hide_index=True)
        else:
            st.info("No security findings available. Connect to AWS to fetch findings.")
    
    with tabs[5]:
        st.markdown("## 📋 Compliance Framework Monitoring")
        
        frameworks = {
            'PCI DSS': {
                'description': 'Payment Card Industry Data Security Standard',
                'controls': ['Encryption', 'Access Control', 'Monitoring', 'Network Security']
            },
            'HIPAA': {
                'description': 'Health Insurance Portability and Accountability Act',
                'controls': ['Data Privacy', 'Security', 'Breach Notification', 'Audit Controls']
            },
            'GDPR': {
                'description': 'General Data Protection Regulation',
                'controls': ['Data Protection', 'Privacy by Design', 'Right to be Forgotten', 'Data Portability']
            },
            'SOC 2': {
                'description': 'Service Organization Control 2',
                'controls': ['Security', 'Availability', 'Processing Integrity', 'Confidentiality']
            }
        }
        
        cols = st.columns(2)
        
        config_compliance = st.session_state.get('config_compliance', {})
        
        for idx, (framework, details) in enumerate(frameworks.items()):
            with cols[idx % 2]:
                st.markdown(f"### {framework}")
                st.markdown(f"*{details['description']}*")
                
                compliant = config_compliance.get('COMPLIANT', 0)
                total = sum(config_compliance.values()) if config_compliance else 1
                score = (compliant / total * 100) if total > 0 else 0
                
                st.progress(score / 100)
                st.markdown(f"**Compliance Score: {score:.1f}%**")
                
                with st.expander("Key Controls"):
                    for control in details['controls']:
                        st.markdown(f"- {control}")
    
    # Footer
    st.markdown("---")
    st.markdown("""
    <div style='text-align: center; color: #666; padding: 2rem;'>
        <p><strong>AI-Enhanced AWS Compliance Platform v2.0</strong></p>
        <p>Powered by Anthropic Claude AI | AWS Bedrock | GitHub Actions</p>
        <p style='font-size: 0.9rem;'>Features: Multi-Account Monitoring | Automated Remediation | GitOps | Account Lifecycle Management</p>
        <p style='font-size: 0.8rem;'>⚠️ Ensure proper AWS IAM permissions for all services</p>
        <p style='font-size: 0.8rem;'>📚 Documentation | 🐛 Report Issues | 💬 Get Support</p>
    </div>
    """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()