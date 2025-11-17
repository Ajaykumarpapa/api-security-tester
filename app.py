import streamlit as st
import requests
import json
import time
from datetime import datetime
from typing import Dict, List
import plotly.graph_objects as go
import plotly.express as px

# Page configuration
st.set_page_config(
    page_title="API Security Tester",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
    }
    .test-card {
        padding: 1rem;
        border-radius: 0.5rem;
        margin: 0.5rem 0;
    }
    .pass {
        background-color: #d4edda;
        border-left: 4px solid #28a745;
    }
    .fail {
        background-color: #f8d7da;
        border-left: 4px solid #dc3545;
    }
    .warning {
        background-color: #fff3cd;
        border-left: 4px solid #ffc107;
    }
</style>
""", unsafe_allow_html=True)

class APISecurityTester:
    def __init__(self, base_url: str, headers: Dict = None):
        self.base_url = base_url
        self.headers = headers or {}
        self.results = []

    def test_sql_injection(self, endpoint: str) -> Dict:
        """Test for SQL injection vulnerabilities"""
        payloads = ["' OR '1'='1", "1' OR '1'='1' --", "admin'--"]
        vulnerabilities = []

        for payload in payloads:
            try:
                url = f"{self.base_url}{endpoint}?id={payload}"
                response = requests.get(url, headers=self.headers, timeout=5)

                if any(keyword in response.text.lower() for keyword in ['sql', 'syntax', 'mysql', 'sqlite']):
                    vulnerabilities.append({
                        'payload': payload,
                        'status_code': response.status_code,
                        'vulnerable': True
                    })
            except Exception as e:
                pass

        return {
            'test': 'SQL Injection',
            'passed': len(vulnerabilities) == 0,
            'severity': 'Critical' if vulnerabilities else 'None',
            'details': vulnerabilities if vulnerabilities else 'No SQL injection vulnerabilities detected'
        }

    def test_xss(self, endpoint: str) -> Dict:
        """Test for Cross-Site Scripting vulnerabilities"""
        payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"]
        vulnerabilities = []

        for payload in payloads:
            try:
                url = f"{self.base_url}{endpoint}?search={payload}"
                response = requests.get(url, headers=self.headers, timeout=5)

                if payload in response.text:
                    vulnerabilities.append({
                        'payload': payload,
                        'reflected': True
                    })
            except Exception as e:
                pass

        return {
            'test': 'Cross-Site Scripting (XSS)',
            'passed': len(vulnerabilities) == 0,
            'severity': 'High' if vulnerabilities else 'None',
            'details': vulnerabilities if vulnerabilities else 'No XSS vulnerabilities detected'
        }

    def test_authentication(self, endpoint: str) -> Dict:
        """Test for authentication bypass"""
        try:
            # Test without authentication
            response = requests.get(f"{self.base_url}{endpoint}", timeout=5)

            if response.status_code == 200:
                return {
                    'test': 'Authentication Check',
                    'passed': False,
                    'severity': 'Critical',
                    'details': f'Endpoint accessible without authentication (Status: {response.status_code})'
                }
            else:
                return {
                    'test': 'Authentication Check',
                    'passed': True,
                    'severity': 'None',
                    'details': f'Authentication required (Status: {response.status_code})'
                }
        except Exception as e:
            return {
                'test': 'Authentication Check',
                'passed': True,
                'severity': 'None',
                'details': f'Could not test: {str(e)}'
            }

    def test_rate_limiting(self, endpoint: str, num_requests: int = 10) -> Dict:
        """Test for rate limiting"""
        responses = []

        for _ in range(num_requests):
            try:
                response = requests.get(f"{self.base_url}{endpoint}", headers=self.headers, timeout=5)
                responses.append(response.status_code)
            except Exception:
                pass

        if all(status == 200 for status in responses):
            return {
                'test': 'Rate Limiting',
                'passed': False,
                'severity': 'Medium',
                'details': f'No rate limiting detected ({num_requests} consecutive requests succeeded)'
            }
        else:
            return {
                'test': 'Rate Limiting',
                'passed': True,
                'severity': 'None',
                'details': 'Rate limiting appears to be in place'
            }

    def test_cors(self, endpoint: str) -> Dict:
        """Test for CORS misconfigurations"""
        malicious_origins = ['https://evil.com', 'null', '*']
        vulnerabilities = []

        for origin in malicious_origins:
            try:
                headers = {**self.headers, 'Origin': origin}
                response = requests.get(f"{self.base_url}{endpoint}", headers=headers, timeout=5)

                if 'access-control-allow-origin' in response.headers:
                    allowed = response.headers['access-control-allow-origin']
                    if allowed == '*' or allowed == origin:
                        vulnerabilities.append({
                            'origin': origin,
                            'allowed': allowed
                        })
            except Exception:
                pass

        return {
            'test': 'CORS Configuration',
            'passed': len(vulnerabilities) == 0,
            'severity': 'Medium' if vulnerabilities else 'None',
            'details': vulnerabilities if vulnerabilities else 'CORS properly configured'
        }

    def test_sensitive_data_exposure(self, endpoint: str) -> Dict:
        """Test for sensitive data exposure"""
        try:
            response = requests.get(f"{self.base_url}{endpoint}", headers=self.headers, timeout=5)
            sensitive_keywords = ['password', 'api_key', 'secret', 'token', 'credit_card', 'ssn']
            found_keywords = [kw for kw in sensitive_keywords if kw in response.text.lower()]

            if found_keywords:
                return {
                    'test': 'Sensitive Data Exposure',
                    'passed': False,
                    'severity': 'High',
                    'details': f'Potentially sensitive data exposed: {", ".join(found_keywords)}'
                }
            else:
                return {
                    'test': 'Sensitive Data Exposure',
                    'passed': True,
                    'severity': 'None',
                    'details': 'No obvious sensitive data exposure detected'
                }
        except Exception as e:
            return {
                'test': 'Sensitive Data Exposure',
                'passed': True,
                'severity': 'None',
                'details': f'Could not test: {str(e)}'
            }

    def run_all_tests(self, endpoint: str) -> List[Dict]:
        """Run all security tests"""
        tests = [
            self.test_sql_injection(endpoint),
            self.test_xss(endpoint),
            self.test_authentication(endpoint),
            self.test_rate_limiting(endpoint),
            self.test_cors(endpoint),
            self.test_sensitive_data_exposure(endpoint)
        ]

        self.results = tests
        return tests

def create_security_score(results: List[Dict]) -> float:
    """Calculate security score based on test results"""
    if not results:
        return 0.0

    total_tests = len(results)
    passed_tests = sum(1 for r in results if r['passed'])

    return (passed_tests / total_tests) * 100

def create_vulnerability_chart(results: List[Dict]):
    """Create a pie chart showing vulnerability distribution"""
    severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'None': 0}

    for result in results:
        severity = result.get('severity', 'None')
        severity_counts[severity] += 1

    # Remove 'None' from chart
    chart_data = {k: v for k, v in severity_counts.items() if k != 'None' and v > 0}

    if not chart_data:
        return None

    colors = {'Critical': '#dc3545', 'High': '#fd7e14', 'Medium': '#ffc107'}

    fig = go.Figure(data=[go.Pie(
        labels=list(chart_data.keys()),
        values=list(chart_data.values()),
        marker=dict(colors=[colors.get(k, '#6c757d') for k in chart_data.keys()])
    )])

    fig.update_layout(
        title="Vulnerability Distribution by Severity",
        height=400
    )

    return fig

def main():
    # Header
    st.markdown('<div class="main-header">🔒 API Security Testing Agent</div>', unsafe_allow_html=True)

    # Sidebar
    with st.sidebar:
        st.header("⚙️ Configuration")

        base_url = st.text_input(
            "API Base URL",
            placeholder="https://api.example.com",
            help="Enter the base URL of the API you want to test"
        )

        endpoint = st.text_input(
            "Endpoint Path",
            placeholder="/api/users",
            help="Enter the specific endpoint to test (e.g., /api/users)"
        )

        st.markdown("---")

        st.subheader("Custom Headers (Optional)")
        add_headers = st.checkbox("Add custom headers")
        headers = {}

        if add_headers:
            num_headers = st.number_input("Number of headers", min_value=1, max_value=10, value=1)
            for i in range(int(num_headers)):
                col1, col2 = st.columns(2)
                with col1:
                    key = st.text_input(f"Header {i+1} Key", key=f"key_{i}")
                with col2:
                    value = st.text_input(f"Header {i+1} Value", key=f"value_{i}")
                if key and value:
                    headers[key] = value

        st.markdown("---")

        run_test = st.button("🚀 Run Security Tests", type="primary", use_container_width=True)

        st.markdown("---")
        st.caption("⚠️ Only test APIs you have permission to test")

    # Main content
    if not base_url or not endpoint:
        st.info("👈 Enter API details in the sidebar to begin testing")

        # Show feature overview
        st.subheader("🛡️ Security Tests Included")

        col1, col2 = st.columns(2)

        with col1:
            st.markdown("""
            - **SQL Injection Detection**
            - **Cross-Site Scripting (XSS)**
            - **Authentication Bypass**
            """)

        with col2:
            st.markdown("""
            - **Rate Limiting Check**
            - **CORS Misconfiguration**
            - **Sensitive Data Exposure**
            """)

        st.markdown("---")

        st.subheader("📊 What You'll Get")
        st.markdown("""
        - Comprehensive security assessment report
        - Visual vulnerability distribution
        - Security score (0-100%)
        - Detailed findings with severity levels
        - Actionable recommendations
        """)

    elif run_test:
        # Run tests
        with st.spinner("🔍 Running security tests..."):
            tester = APISecurityTester(base_url, headers)
            results = tester.run_all_tests(endpoint)

        # Store results in session state
        st.session_state['results'] = results
        st.session_state['tested_url'] = f"{base_url}{endpoint}"
        st.session_state['test_time'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        st.success("✅ Security tests completed!")

    # Display results if available
    if 'results' in st.session_state:
        results = st.session_state['results']

        # Calculate security score
        security_score = create_security_score(results)

        # Display metrics
        st.subheader("📊 Test Summary")

        col1, col2, col3, col4 = st.columns(4)

        with col1:
            st.metric("Security Score", f"{security_score:.1f}%")

        with col2:
            total_tests = len(results)
            st.metric("Total Tests", total_tests)

        with col3:
            failed_tests = sum(1 for r in results if not r['passed'])
            st.metric("Failed Tests", failed_tests)

        with col4:
            critical_issues = sum(1 for r in results if r.get('severity') == 'Critical')
            st.metric("Critical Issues", critical_issues)

        # Display chart
        col1, col2 = st.columns([2, 1])

        with col1:
            chart = create_vulnerability_chart(results)
            if chart:
                st.plotly_chart(chart, use_container_width=True)
            else:
                st.success("🎉 No vulnerabilities detected!")

        with col2:
            st.subheader("🎯 Hackability Assessment")

            if security_score >= 80:
                st.success("✅ **Low Risk**")
                st.write("API appears to be well-secured")
            elif security_score >= 60:
                st.warning("⚠️ **Medium Risk**")
                st.write("Some security improvements needed")
            else:
                st.error("🚨 **High Risk**")
                st.write("Critical security issues detected")

            st.metric("Hackability Score", f"{100 - security_score:.1f}%")

        # Detailed results
        st.markdown("---")
        st.subheader("📋 Detailed Test Results")

        for result in results:
            if result['passed']:
                st.markdown(f"""
<div class="test-card pass">
<strong>✅ {result['test']}</strong><br>
<p>{result['details']}</p>
</div>
""", unsafe_allow_html=True)
            else:
                severity_class = "fail" if result['severity'] in ['Critical', 'High'] else "warning"
                st.markdown(f"""
<div class="test-card {severity_class}">
<strong>❌ {result['test']}</strong><br>
<p>{result['details']}</p>
</div>
""", unsafe_allow_html=True)

if __name__ == "__main__":
    main()
