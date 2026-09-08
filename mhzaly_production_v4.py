#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MHZALY BUG BOUNTY & ENTERPRISE SECURITY PLATFORM v10.2 - STABLE CHATBOT EDITION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Comprehensive Offensive Security, Bug Bounty Recon & Blue Team SOC Suite
- Interactive AI Security Chatbot (Powered by Groq Llama 3.1 8B Instant)
- Real-Time Target Fingerprinting & Sensitive Endpoint Fuzzing
- NVD v2.0 REST Client with Accelerated API Key Support
- Live VirusTotal & AbuseIPDB Threat Intelligence Triage (Domain & IP Safe Guard)
- Advanced Network Recon: DNS Enumeration, Port Scanning, SSL & Headers Audit
- Offensive Payload Encoder, Decoder & Hashing Utility
- SQLite Persistence & Audit Log History Tracking

Author: Muhammad Hassaan Zahid
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

import streamlit as st
import requests
import pandas as pd
import numpy as np
import json
import sqlite3
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
import socket
import ssl
import dns.resolver
import re
import urllib.parse
import base64
import hashlib

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Disable insecure request warnings for offensive reconnaissance
requests.packages.urllib3.disable_warnings()

# ═══════════════════════════════════════════════════════════════════════════════
# 1. DATA MODELS & SCHEMAS
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class VulnerabilityRecord:
    cve_id: str
    title: str
    description: str
    severity: str
    cvss_score: float
    vector_string: str
    affected_configurations: List[str]
    published_date: str
    remediation: str

    def to_dict(self):
        return asdict(self)

# ═══════════════════════════════════════════════════════════════════════════════
# 2. ENTERPRISE RECON & INTELLIGENCE ENGINES
# ═══════════════════════════════════════════════════════════════════════════════

class BugBountyReconEngine:
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
        for rtype in ['A', 'AAAA', 'MX', 'TXT', 'NS', 'SOA']:
            try:
                answers = dns.resolver.resolve(parsed_domain, rtype)
                report['dns'][rtype] = [str(r) for r in answers]
            except Exception:
                report['dns'][rtype] = []

        # 2. HTTP Probing & Fingerprinting
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) BugBountyEliteHunter/8.0'
        })
        
        try:
            resp = session.get(target_url, timeout=8, verify=False, allow_redirects=True)
            report['status_code'] = resp.status_code
            report['server'] = resp.headers.get('Server', 'Hidden / Unknown')
            
            body = resp.text.lower()
            headers_str = str(resp.headers).lower()
            
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
                report['technologies'].append('Amazon AWS Cloud Infrastructure')

            fuzz_paths = [
                '/.env', '/robots.txt', '/sitemap.xml', '/git/config', 
                '/backup.zip', '/api/v1/users', '/swagger.ui', '/phpinfo.php',
                '/config.json', '/auth/login', '/graphql', '/debug', '/admin',
                '/server-status', '/xmlrpc.php', '/package.json', '/composer.json'
            ]
            
            base_origin = f"{urllib.parse.urlparse(target_url).scheme}://{urllib.parse.urlparse(target_url).netloc}"
            
            for path in fuzz_paths:
                test_url = base_origin + path
                try:
                    p_resp = session.get(test_url, timeout=3, verify=False)
                    if p_resp.status_code in [200, 403]:
                        if p_resp.status_code == 200 and len(p_resp.text) > 10:
                            if any(err in p_resp.text.lower() for err in ["not found", "404 page", "does not exist", "object not found"]):
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
    """NVD v2.0 Client with Accelerated API Key Support"""
    def __init__(self, nvd_key: str = ""):
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.nvd_key = nvd_key

    def search_cve(self, keyword: str, max_results: int = 15) -> List[VulnerabilityRecord]:
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
                    
                    score = 0.0
                    severity = "UNKNOWN"
                    vector = "N/A"
                    metrics = cve.get('metrics', {})
                    if 'cvssMetricV31' in metrics:
                        cvss_data = metrics['cvssMetricV31'][0].get('cvssData', {})
                        score = cvss_data.get('baseScore', 0.0)
                        severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                        vector = cvss_data.get('vectorString', 'N/A')
                    elif 'cvssMetricV30' in metrics:
                        cvss_data = metrics['cvssMetricV30'][0].get('cvssData', {})
                        score = cvss_data.get('baseScore', 0.0)
                        severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                        vector = cvss_data.get('vectorString', 'N/A')
                        
                    vulnerabilities.append(VulnerabilityRecord(
                        cve_id=cve_id,
                        title=cve_id,
                        description=desc,
                        severity=severity.upper(),
                        cvss_score=float(score),
                        vector_string=vector,
                        affected_configurations=[keyword],
                        published_date=cve.get('published', '')[:10],
                        remediation=f"Apply official vendor patch or configure WAF signature to mitigate {cve_id}."
                    ))
        except Exception as e:
            logger.error(f"NVD API Error: {e}")
        return vulnerabilities

class ThreatIntelService:
    """Live VirusTotal & AbuseIPDB Triage Engine (Strictly Domain & IP Safe)"""
    def __init__(self, vt_key: str, abuse_key: str):
        self.vt_key = vt_key
        self.abuse_key = abuse_key

    def triage_indicator(self, indicator: str) -> Dict[str, Any]:
        results = {'indicator': indicator, 'virustotal': None, 'abuseipdb': None}
        is_ip = bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', indicator))
        is_url = indicator.startswith(('http://', 'https://'))

        if self.vt_key:
            try:
                headers = {'x-apikey': self.vt_key}
                if is_url:
                    url = f"https://www.virustotal.com/api/v3/urls/{urllib.parse.quote(indicator, safe='')}"
                elif is_ip:
                    url = f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}"
                else:
                    url = f"https://www.virustotal.com/api/v3/domains/{indicator}"
                resp = requests.get(url, headers=headers, timeout=10)
                if resp.status_code == 200:
                    results['virustotal'] = resp.json()
                else:
                    results['virustotal'] = {'error': f"VirusTotal HTTP Status Code: {resp.status_code}"}
            except Exception as e:
                results['virustotal'] = {'error': str(e)}
        else:
            results['virustotal'] = {'error': 'VirusTotal API key is not configured in secrets.'}

        if self.abuse_key:
            if is_ip:
                try:
                    headers = {'Key': self.abuse_key, 'Accept': 'application/json'}
                    params = {'ipAddress': indicator, 'maxAgeInDays': 90, 'verbose': True}
                    resp = requests.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params=params, timeout=10)
                    if resp.status_code == 200:
                        results['abuseipdb'] = resp.json()
                    else:
                        results['abuseipdb'] = {'error': f"AbuseIPDB HTTP Status Code: {resp.status_code}"}
                except Exception as e:
                    results['abuseipdb'] = {'error': str(e)}
            else:
                results['abuseipdb'] = {'info': 'Skipped AbuseIPDB query because input is a Domain or URL (AbuseIPDB only accepts IPv4/IPv6 addresses).'}
        else:
            results['abuseipdb'] = {'error': 'AbuseIPDB API key is not configured in secrets.'}

        return results

class AdvancedReconEngine:
    """Network Recon & Infrastructure Audit Module"""
    @staticmethod
    def audit_infrastructure(domain: str) -> Dict[str, Any]:
        report = {}
        dns_records = {}
        for rtype in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']:
            try:
                answers = dns.resolver.resolve(domain, rtype)
                dns_records[rtype] = [str(r) for r in answers]
            except Exception:
                dns_records[rtype] = []
        report['dns'] = dns_records

        common_ports = [21, 22, 25, 53, 80, 110, 443, 445, 3306, 3389, 8080, 8443]
        open_ports = []
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.0)
                res = sock.connect_ex((domain, port))
                sock.close()
                if res == 0:
                    service_name = {
                        21: 'FTP', 22: 'SSH', 25: 'SMTP', 53: 'DNS', 80: 'HTTP',
                        110: 'POP3', 443: 'HTTPS', 445: 'SMB', 3306: 'MySQL',
                        3389: 'RDP', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt'
                    }.get(port, 'Unknown')
                    open_ports.append({'port': port, 'service': service_name, 'status': 'OPEN'})
            except Exception:
                pass
        report['ports'] = open_ports

        ssl_info = {'valid': False, 'details': {}}
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((domain, 443), timeout=3) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    if cert:
                        ssl_info['valid'] = True
                        ssl_info['details'] = {
                            'subject': dict(x[0] for x in cert.get('subject', [])),
                            'issuer': dict(x[0] for x in cert.get('issuer', [])),
                            'version': cert.get('version'),
                            'not_before': cert.get('notBefore'),
                            'not_after': cert.get('notAfter')
                        }
        except Exception as e:
            ssl_info['error'] = str(e)
        report['ssl'] = ssl_info

        headers_report = {}
        try:
            resp = requests.get(f"https://{domain}", timeout=5, verify=False)
            target_headers = [
                'Strict-Transport-Security', 'Content-Security-Policy',
                'X-Frame-Options', 'X-Content-Type-Options', 'X-XSS-Protection'
            ]
            for h in target_headers:
                headers_report[h] = resp.headers.get(h, 'MISSING')
        except Exception as e:
            headers_report['error'] = str(e)
        report['headers'] = headers_report

        return report

class SecurityDatabase:
    """SQLite Persistence Database for Activity Logging"""
    def __init__(self, db_path: str = "security_platform.db"):
        self.db_path = db_path
        self.init_db()

    def init_db(self):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS activity_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    module TEXT,
                    target TEXT,
                    timestamp DATETIME,
                    status TEXT
                )
            """)
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Database error: {e}")

    def log_activity(self, module: str, target: str, status: str):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("INSERT INTO activity_logs (module, target, timestamp, status) VALUES (?, ?, ?, ?)",
                           (module, target, datetime.now(), status))
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Log error: {e}")

    def get_history(self) -> List[Dict]:
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT module, target, timestamp, status FROM activity_logs ORDER BY timestamp DESC LIMIT 50")
            rows = cursor.fetchall()
            conn.close()
            return [{'module': r[0], 'target': r[1], 'timestamp': r[2], 'status': r[3]} for r in rows]
        except Exception:
            return []

# ═══════════════════════════════════════════════════════════════════════════════
# 3. STREAMLIT ENTERPRISE UI
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    st.set_page_config(
        page_title="MHZALY AI Security Chatbot Suite",
        page_icon="🤖",
        layout="wide",
        initial_sidebar_state="expanded"
    )

    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False

    if not st.session_state.authenticated:
        col1, col2, col3 = st.columns([1, 1.2, 1])
        with col2:
            st.markdown("<br><br>", unsafe_allow_html=True)
            st.markdown("# MHZALY Enterprise Login")
            st.markdown("##### Bug Bounty & Security Operations Suite")
            
            username = st.text_input("Operator Username")
            password = st.text_input("Operator Password", type="password")
            
            if st.button("Authenticate Suite", use_container_width=True, type="primary"):
                correct_user = st.secrets.get("APP_USERNAME", "admin")
                correct_pass = st.secrets.get("APP_PASSWORD", "admin123")
                if username == correct_user and password == correct_pass:
                    st.session_state.authenticated = True
                    st.session_state.user = username
                    st.success("Authentication successful. Initializing modules...")
                    st.rerun()
                else:
                    st.error("Authentication failed: Invalid credentials.")
        return

    vt_key = st.secrets.get("VIRUSTOTAL_API_KEY", "")
    abuse_key = st.secrets.get("ABUSEIPDB_API_KEY", "")
    groq_key = st.secrets.get("GROQ_API_KEY", "")
    nvd_key = st.secrets.get("NVD_API_KEY", "")
    
    db = SecurityDatabase()

    with st.sidebar:
        st.markdown(f"### Operator: `{st.session_state.user}`")
        st.markdown("---")
        module = st.radio(
            "Navigation Menu",
            [
                "🤖 AI Security Chatbot",
                "Command Telemetry Center",
                "Bug Bounty Recon & Fuzzing",
                "Network Infrastructure Audit",
                "Enterprise NVD Intelligence",
                "Threat Intel & IOC Triage",
                "Offensive Encoder & Hasher",
                "Activity History & Logs",
                "Platform Configuration"
            ]
        )
        st.markdown("---")
        if st.button("Terminate Session", use_container_width=True):
            st.session_state.authenticated = False
            st.rerun()

    if module == "🤖 AI Security Chatbot":
        st.markdown("# AI Security Operations & Bug Bounty Chatbot")
        st.markdown("Ask anything about security, exploit vectors, WAF bypass, or Sigma detection rules. Powered by Groq AI.")

        if "messages" not in st.session_state:
            st.session_state.messages = [
                {"role": "assistant", "content": "Hello operator! I am your MHZALY AI Security Assistant backed by your active API keys. How can I assist your bug bounty or SOC operations today?"}
            ]

        for message in st.session_state.messages:
            with st.chat_message(message["role"]):
                st.markdown(message["content"])

        if prompt := st.chat_input("Ask a security query or request a payload/playbook..."):
            st.session_state.messages.append({"role": "user", "content": prompt})
            with st.chat_message("user"):
                st.markdown(prompt)

            with st.chat_message("assistant"):
                if not groq_key:
                    response_text = "❌ Error: Groq API Key is not configured in your Streamlit secrets."
                    st.markdown(response_text)
                else:
                    with st.spinner("Analyzing via Groq AI..."):
                        try:
                            headers = {'Authorization': f'Bearer {groq_key}', 'Content-Type': 'application/json'}
                            payload = {
                                'model': 'llama-3.1-8b-instant',
                                'messages': [
                                    {'role': 'system', 'content': 'You are an elite Cybersecurity Expert, Bug Bounty Mentor, and Red/Blue Team Advisor. Provide detailed code, payloads, and defense mechanisms.'},
                                    *[ {'role': m['role'], 'content': m['content']} for m in st.session_state.messages ]
                                ],
                                'temperature': 0.6,
                                'max_tokens': 1500
                            }
                            resp = requests.post("https://api.groq.com/openai/v1/chat/completions", json=payload, headers=headers, timeout=25)
                            if resp.status_code == 200:
                                response_text = resp.json()['choices'][0]['message']['content']
                            else:
                                response_text = f"API Error Code: {resp.status_code} - {resp.text}"
                        except Exception as e:
                            response_text = f"Connection failed: {e}"
                    st.markdown(response_text)
            st.session_state.messages.append({"role": "assistant", "content": response_text})

    elif module == "Command Telemetry Center":
        st.markdown("# Security Operations Center - Command Dashboard")
        st.markdown("Aggregated telemetry across offensive recon nodes and defensive monitoring.")
        
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Threat Level", "ELEVATED", "Orange")
        c2.metric("NVD API Key", "Accelerated" if nvd_key else "Standard", "NIST v2.0")
        c3.metric("Groq AI Chatbot", "Online" if groq_key else "Offline", "llama-3.1-8b-instant")
        c4.metric("SQLite DB", "Connected", "Active")

    elif module == "Bug Bounty Recon & Fuzzing":
        st.markdown("# Target Reconnaissance & Sensitive Endpoint Fuzzing")
        target_input = st.text_input("Target URL or Domain", placeholder="e.g., target-domain.com")
        
        if st.button("Launch Recon & Asset Discovery", type="primary", use_container_width=True):
            if target_input:
                with st.spinner(f"Executing deep offensive reconnaissance on {target_input}..."):
                    recon = BugBountyReconEngine.deep_recon(target_input)
                    db.log_activity("Bug Bounty Recon", target_input, "Completed")
                    st.success("Reconnaissance cycle complete.")
                    
                    c1, c2, c3 = st.columns(3)
                    c1.metric("HTTP Status", recon.get('status_code', 'N/A'))
                    c2.metric("Web Server Banner", recon.get('server', 'N/A'))
                    c3.metric("Exposed Endpoints", len(recon.get('exposed_files', [])))
                    
                    st.markdown("### Authoritative DNS Records")
                    for rtype, recs in recon.get('dns', {}).items():
                        if recs:
                            st.markdown(f"**{rtype} Records:**")
                            for r in recs:
                                st.code(r)
                                
                    st.markdown("### Fingerprinted Technology Stack")
                    techs = recon.get('technologies', [])
                    if techs:
                        for t in techs:
                            st.markdown(f"- `{t}`")
                    else:
                        st.info("No prominent framework signatures found.")
                        
                    st.markdown("### Exposed Sensitive Endpoints & Backup Files")
                    exposed = recon.get('exposed_files', [])
                    if exposed:
                        st.dataframe(pd.DataFrame(exposed), use_container_width=True)
                        json_report = json.dumps(recon, indent=2)
                        st.download_button(
                            "Export Recon Report (JSON)",
                            data=json_report,
                            file_name=f"recon_{target_input.replace('/', '_')}.json",
                            mime="application/json"
                        )
                    else:
                        st.info("No common sensitive files discovered on standard paths.")
            else:
                st.warning("Please specify a target domain or URL.")

    elif module == "Network Infrastructure Audit":
        st.markdown("# Red/Blue Team Infrastructure Reconnaissance & Audit")
        target_domain = st.text_input("Target Domain or IP Address", placeholder="e.g., scanme.nmap.org")
        
        if st.button("Execute Full Infrastructure Audit", type="primary", use_container_width=True):
            if target_domain:
                with st.spinner(f"Executing infrastructure audit against {target_domain}..."):
                    audit_data = AdvancedReconEngine.audit_infrastructure(target_domain)
                    db.log_activity("Infrastructure Audit", target_domain, "Completed")
                    st.success("Infrastructure Audit Completed Successfully.")

                    tab1, tab2, tab3, tab4 = st.tabs(["DNS Records", "Port Scan", "SSL / TLS", "Security Headers"])
                    
                    with tab1:
                        for rtype, recs in audit_data['dns'].items():
                            if recs:
                                st.markdown(f"**{rtype} Records:**")
                                for r in recs:
                                    st.code(r)
                    with tab2:
                        ports = audit_data['ports']
                        if ports:
                            st.dataframe(pd.DataFrame(ports), use_container_width=True)
                        else:
                            st.info("No open ports found on scanned standard ports.")
                    with tab3:
                        ssl_res = audit_data['ssl']
                        if ssl_res.get('valid'):
                            st.success("Valid SSL/TLS Certificate Deployed.")
                            st.json(ssl_res['details'])
                        else:
                            st.warning(f"SSL Issue: {ssl_res.get('error', 'Unknown')}")
                    with tab4:
                        headers = audit_data['headers']
                        if 'error' in headers:
                            st.error(f"Error: {headers['error']}")
                        else:
                            for h_name, h_val in headers.items():
                                icon = "❌" if h_val == 'MISSING' else "✅"
                                st.write(f"{icon} **{h_name}:** `{h_val}`")
            else:
                st.warning("Please provide a valid target host.")

    elif module == "Enterprise NVD Intelligence":
        st.markdown("# Enterprise NVD Vulnerability Intelligence")
        keyword = st.text_input("Search Software / Vendor / CVE", placeholder="e.g., apache, wordpress plugin, cve-2024")
        
        if st.button("Query NVD Database", type="primary", use_container_width=True):
            if keyword:
                with st.spinner("Fetching CVE telemetry from NIST NVD..."):
                    client = NVDIntelligenceClient(nvd_key)
                    vulns = client.search_cve(keyword)
                    db.log_activity("NVD Research", keyword, f"Found {len(vulns)} CVEs")
                    
                    if vulns:
                        st.success(f"Retrieved {len(vulns)} CVE records.")
                        for v in vulns:
                            with st.expander(f"{v.cve_id} | Severity: {v.severity} | CVSS: {v.cvss_score}"):
                                st.markdown(f"**Published:** {v.published_date}")
                                st.markdown(f"**Vector:** `{v.vector_string}`")
                                st.write(v.description)
                                st.markdown(f"**Remediation:** {v.remediation}")
                    else:
                        st.info("No matching records found in NVD.")
            else:
                st.warning("Please enter a search keyword.")

    elif module == "Threat Intel & IOC Triage":
        st.markdown("# Live Threat Intelligence & IOC Triage")
        indicator = st.text_input("Enter Indicator (IP Address, Domain, or URL)", placeholder="e.g., 8.8.8.8 or example.com")
        
        if st.button("Run Threat Triage", type="primary", use_container_width=True):
            if indicator:
                with st.spinner("Querying live threat feeds..."):
                    ti = ThreatIntelService(vt_key, abuse_key)
                    report = ti.triage_indicator(indicator)
                    db.log_activity("Threat Intel Triage", indicator, "Completed")
                    st.success("Triage Analysis Complete.")
                    
                    c1, c2 = st.columns(2)
                    with c1:
                        st.subheader("VirusTotal Intelligence")
                        if vt_key:
                            st.json(report['virustotal'])
                        else:
                            st.info("VirusTotal API Key not configured.")
                    with c2:
                        st.subheader("AbuseIPDB Reputation")
                        if abuse_key:
                            st.json(report['abuseipdb'])
                        else:
                            st.info("AbuseIPDB API Key not configured or skipped.")
            else:
                st.warning("Please provide an indicator.")

    elif module == "Offensive Encoder & Hasher":
        st.markdown("# Offensive Payload Encoder, Decoder & Hasher")
        input_text = st.text_input("Input String / Payload", placeholder="Enter text to encode, decode, or hash...")
        
        col_enc1, col_enc2 = st.columns(2)
        with col_enc1:
            if st.button("Base64 Encode", use_container_width=True):
                if input_text:
                    encoded = base64.b64encode(input_text.encode()).decode()
                    st.code(encoded)
            if st.button("URL Encode", use_container_width=True):
                if input_text:
                    encoded = urllib.parse.quote(input_text)
                    st.code(encoded)
        with col_enc2:
            if st.button("Base64 Decode", use_container_width=True):
                if input_text:
                    try:
                        decoded = base64.b64decode(input_text.encode()).decode()
                        st.code(decoded)
                    except Exception as e:
                        st.error(f"Decoding error: {e}")
            if st.button("Generate Hashes (MD5 / SHA256)", use_container_width=True):
                if input_text:
                    md5_h = hashlib.md5(input_text.encode()).hexdigest()
                    sha_h = hashlib.sha256(input_text.encode()).hexdigest()
                    st.markdown(f"**MD5:** `{md5_h}`")
                    st.markdown(f"**SHA256:** `{sha_h}`")

    elif module == "Activity History & Logs":
        st.markdown("# Activity History & SQLite Audit Logs")
        history = db.get_history()
        if history:
            st.dataframe(pd.DataFrame(history), use_container_width=True)
        else:
            st.info("No recorded activity logs found.")

    elif module == "Platform Configuration":
        st.markdown("# Platform Telemetry & API Status")
        st.write(f"**NVD API Key:** {'Accelerated' if nvd_key else 'Standard'}")
        st.write(f"**VirusTotal API:** {'Active' if vt_key else 'Missing'}")
        st.write(f"**AbuseIPDB API:** {'Active' if abuse_key else 'Missing'}")
        st.write(f"**Groq AI Chatbot:** {'Active (llama-3.1-8b-instant)' if groq_key else 'Missing'}")
        st.write("**SQLite Database:** Initialized")

if __name__ == "__main__":
    main()
