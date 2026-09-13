#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NAQAAB50 BUG BOUNTY & ENTERPRISE SECURITY PLATFORM v18.1 - ELITE HACKER EDITION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Comprehensive Purple Team Operations Suite (Red Team Recon + Blue Team SOC Automation)
- Cyberpunk Dark Hacker Theme with Monospace Fonts, Glowing Neon Accents & Sleek Cards
- Dual Authentication Gateway: Operator Email/Password (Sign In / Create Account with Email OTP Verification) + Real Google OAuth
- Personal Persistent API Key Vault (SQLite-backed operator key management)
- 100% Autonomous AI-Agent Pipeline with Soft-404 Filtering & Smart CVSS Thresholds
- Fully Automated Enterprise Security Assessment Report Generator & Exporter (.md, .json, .csv)
- Dedicated Interactive AI Security Chatbot (Powered by Groq GPT-OSS 120B)
- Separate Automated Sigma Rule & YARA Detection Generator Module
- Autonomous Target Fingerprinting, Smart Endpoint Fuzzing & Log Parsing Simulator
- NVD v2.0 REST Client with AI-Driven Dynamic Query Refinement & Safety Filters
- Deep Live VirusTotal & AbuseIPDB Threat Intelligence Triage with Granular Safe Parsing
- Advanced Network Recon: Real-time Multi-threaded Port Scanning, DNS, SSL & Headers Audit
- Offensive/Defensive Payload Encoder, Decoder, Hasher & Custom Mutator Utility
- SQLite Persistence & Audit Log History Tracking

Author: Muhammad Hassaan Zahid (Rebranded to Naqaab50)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

import streamlit as st
import requests
import pandas as pd
import numpy as np
import json
import sqlite3
import logging
import time
import hmac
import ipaddress
import random
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, asdict
import socket
import ssl
import dns.resolver
import re
import urllib.parse
import base64
import hashlib
import concurrent.futures

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Disable insecure request warnings for offensive reconnaissance
requests.packages.urllib3.disable_warnings()

# ═══════════════════════════════════════════════════════════════════════════════
# 0. SAFETY: SSRF GUARD, RETRY HELPER, LIGHTWEIGHT CACHE
# ═══════════════════════════════════════════════════════════════════════════════

class ScopeViolation(Exception):
    """Raised when a target resolves to a disallowed internal/metadata address."""
    pass


def assert_public_host(hostname: str) -> None:
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as e:
        raise ScopeViolation(f"Could not resolve host: {e}")

    for family, _, _, _, sockaddr in infos:
        ip_str = sockaddr[0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
            raise ScopeViolation(
                f"Target '{hostname}' resolves to a non-public address ({ip_str}). "
                f"Refusing to scan internal/reserved network space."
            )
        if ip_str == "169.254.169.254":
            raise ScopeViolation("Refusing to scan the cloud metadata endpoint.")


def with_retry(fn: Callable, *args, retries: int = 2, backoff: float = 1.5, **kwargs):
    last_exc = None
    for attempt in range(retries + 1):
        try:
            return fn(*args, **kwargs)
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
            last_exc = e
            if attempt < retries:
                time.sleep(backoff ** attempt)
    raise last_exc


class TTLCache:
    def __init__(self, ttl_seconds: int = 900):
        self.ttl = ttl_seconds
        self._store: Dict[str, Any] = {}

    def get(self, key: str):
        entry = self._store.get(key)
        if not entry:
            return None
        value, expires_at = entry
        if time.time() > expires_at:
            self._store.pop(key, None)
            return None
        return value

    def set(self, key: str, value: Any):
        self._store[key] = (value, time.time() + self.ttl)


@st.cache_resource
def get_shared_cache() -> TTLCache:
    return TTLCache(ttl_seconds=900)


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
    match_confidence: str = "keyword"

    def to_dict(self):
        return asdict(self)


def compute_risk_score(vt_malicious: int, abuse_score: int, top_cvss: float,
                       exposed_count: int = 0, missing_headers: int = 0,
                       risky_open_ports: int = 0) -> Dict[str, Any]:
    vt_component = min(vt_malicious * 8, 40)
    abuse_component = min(abuse_score * 0.3, 30)
    cvss_component = min((top_cvss / 10) * 30, 30)
    exposure_component = min(exposed_count * 6, 24)
    header_component = min(missing_headers * 2.5, 12.5)
    port_component = min(risky_open_ports * 5, 15)

    score = round(
        vt_component + abuse_component + cvss_component +
        exposure_component + header_component + port_component,
        1,
    )
    score = min(score, 100.0)

    if score >= 70:
        band = "CRITICAL"
    elif score >= 45:
        band = "ELEVATED"
    elif score >= 20:
        band = "GUARDED"
    else:
        band = "LOW"
    return {"score": score, "band": band}


RISKY_PUBLIC_PORTS = {3389, 3306, 1433, 5432, 9200, 445, 21}


# ═══════════════════════════════════════════════════════════════════════════════
# 1.5 INPUT VALIDATION & DB MANAGEMENT (USERS + API VAULT + LOGS)
# ═══════════════════════════════════════════════════════════════════════════════

_HOSTNAME_RE = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$'
)
_IPV4_RE = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')


def validate_target_input(raw_target: str, allow_url: bool = True) -> Optional[str]:
    if raw_target is None:
        return "Target is required."
    target = raw_target.strip()
    if not target:
        return "Target cannot be empty."
    if len(target) > 253:
        return "Target is too long to be a valid hostname/URL."
    if any(ch.isspace() for ch in target) or '\x00' in target:
        return "Target must not contain whitespace or control characters."

    if allow_url and target.startswith(('http://', 'https://')):
        parsed = urllib.parse.urlparse(target)
        if not parsed.netloc:
            return "URL is malformed — missing host."
        host = parsed.hostname or ''
        if _IPV4_RE.match(host) or _HOSTNAME_RE.match(host) or host == 'localhost':
            return None
        return "URL host does not look like a valid domain or IP."

    clean = target.split('/')[0]
    if _IPV4_RE.match(clean):
        octets = clean.split('.')
        if all(0 <= int(o) <= 255 for o in octets):
            return None
        return "IP address octets must be between 0 and 255."
    if _HOSTNAME_RE.match(clean):
        return None
    return "Target must be a valid domain (example.com), IPv4 address, or http(s) URL."


DEFAULT_SESSION_TIMEOUT_MINUTES = 30
DEFAULT_MAX_ACTIVE_SCANS_PER_DAY = 100


def enforce_session_timeout(timeout_minutes: int) -> bool:
    now = time.time()
    last_activity = st.session_state.get('last_activity_ts', now)
    if now - last_activity > timeout_minutes * 60:
        st.session_state.authenticated = False
        st.warning(f"Session expired after {timeout_minutes} minutes of inactivity. Please log in again.")
        st.rerun()
        return False
    st.session_state['last_activity_ts'] = now
    return True


def check_and_increment_scan_quota(operator: str, max_per_day: int) -> Optional[str]:
    today = datetime.now().strftime('%Y-%m-%d')
    quota_key = 'scan_quota'
    quota_state = st.session_state.get(quota_key, {})
    day_state = quota_state.get(operator, {'date': today, 'count': 0})
    if day_state['date'] != today:
        day_state = {'date': today, 'count': 0}
    if day_state['count'] >= max_per_day:
        return f"Daily active-scan quota reached ({max_per_day}/day) for operator `{operator}`."
    day_state['count'] += 1
    quota_state[operator] = day_state
    st.session_state[quota_key] = quota_state
    return None


def send_otp_email(receiver_email: str, otp_code: str) -> bool:
    try:
        sender_email = st.secrets["smtp"]["EMAIL_SENDER"]
        sender_password = st.secrets["smtp"]["EMAIL_PASSWORD"]
    except Exception:
        try:
            sender_email = st.secrets.get("EMAIL_SENDER", "muhammadhassaanaly@gmail.com")
            sender_password = st.secrets.get("EMAIL_PASSWORD", "rzqiejtisddoappv")
        except Exception:
            logger.warning("SMTP secrets not found. Simulating email dispatch.")
            return True

    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = receiver_email
    message["Subject"] = "Naqaab50 - Email Verification OTP"

    body = f"Aapka Naqaab50 verification code yeh hai: {otp_code}\nYeh code sirf kuch der ke liye valid hai."
    message.attach(MIMEText(body, "plain"))

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, receiver_email, message.as_string())
        server.quit()
        return True
    except Exception as e:
        logger.error(f"SMTP Dispatch Error: {e}")
        return False


class SecurityDatabase:
    def __init__(self, db_path: str = "naqaab50_platform.db"):
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
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    vt_key TEXT DEFAULT '',
                    abuse_key TEXT DEFAULT '',
                    groq_key TEXT DEFAULT '',
                    nvd_key TEXT DEFAULT '',
                    created_at DATETIME
                )
            """)
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Database error: {e}")

    def create_user(self, email: str, password: str) -> bool:
        try:
            pwd_hash = hashlib.sha256(password.encode()).hexdigest()
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (email, password_hash, created_at) VALUES (?, ?, ?)",
                           (email, pwd_hash, datetime.now()))
            conn.commit()
            conn.close()
            return True
        except sqlite3.IntegrityError:
            return False
        except Exception as e:
            logger.error(f"User creation error: {e}")
            return False

    def verify_user(self, email: str, password: str) -> bool:
        try:
            pwd_hash = hashlib.sha256(password.encode()).hexdigest()
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM users WHERE email = ? AND password_hash = ?", (email, pwd_hash))
            row = cursor.fetchone()
            conn.close()
            return row is not None
        except Exception as e:
            logger.error(f"User verification error: {e}")
            return False

    def get_user_keys(self, email: str) -> Dict[str, str]:
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT vt_key, abuse_key, groq_key, nvd_key FROM users WHERE email = ?", (email,))
            row = cursor.fetchone()
            conn.close()
            if row:
                return {"vt": row[0] or "", "abuse": row[1] or "", "groq": row[2] or "", "nvd": row[3] or ""}
        except Exception as e:
            logger.error(f"Get keys error: {e}")
        return {"vt": "", "abuse": "", "groq": "", "nvd": ""}

    def update_user_keys(self, email: str, vt: str, abuse: str, groq: str, nvd: str):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET vt_key = ?, abuse_key = ?, groq_key = ?, nvd_key = ? WHERE email = ?",
                           (vt, abuse, groq, nvd, email))
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Update keys error: {e}")

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
# 2. ENTERPRISE RECON, SOC & AI-AGENTIC INTELLIGENCE ENGINES
# ═══════════════════════════════════════════════════════════════════════════════

class SubdomainEnumEngine:
    @staticmethod
    def enumerate(domain: str, limit: int = 50) -> List[str]:
        clean = domain.replace('https://', '').replace('http://', '').split('/')[0]
        try:
            resp = with_retry(
                requests.get,
                f"https://crt.sh/?q=%25.{clean}&output=json",
                timeout=12,
            )
            if resp.status_code != 200:
                return []
            data = resp.json()
            names = set()
            for entry in data:
                for name in str(entry.get('name_value', '')).split('\n'):
                    name = name.strip().lower()
                    if name and '*' not in name and name.endswith(clean):
                        names.add(name)
            return sorted(names)[:limit]
        except Exception as e:
            logger.warning(f"crt.sh enumeration failed: {e}")
            return []


class BugBountyReconEngine:
    @staticmethod
    def deep_recon(target: str) -> Dict[str, Any]:
        report = {'target': target, 'status_code': None, 'server': 'Hidden / Unknown', 'technologies': [], 'exposed_files': [], 'dns': {}}
        try:
            clean_target = target.replace('https://', '').replace('http://', '').split('/')[0]
            target_url = f"https://{target}" if not target.startswith(('http://', 'https://')) else target

            assert_public_host(clean_target)

            for rtype in ['A', 'AAAA', 'MX', 'TXT', 'NS', 'SOA']:
                try:
                    answers = dns.resolver.resolve(clean_target, rtype)
                    report['dns'][rtype] = list(set([str(r) for r in answers]))
                except Exception:
                    report['dns'][rtype] = []

            session = requests.Session()
            session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Naqaab50Hunter/18.0'})

            resp = with_retry(session.get, target_url, timeout=8, verify=False, allow_redirects=True)
            report['status_code'] = resp.status_code
            report['server'] = resp.headers.get('Server', 'Hidden / Unknown')

            base_homepage_text = resp.text.lower()
            body = base_homepage_text
            headers_str = str(resp.headers).lower()

            if 'wp-content' in body or 'wordpress' in headers_str:
                report['technologies'].append('WordPress')
            if 'laravel' in headers_str or 'laravel_session' in str(resp.cookies):
                report['technologies'].append('Laravel')
            if 'react' in body or '_next' in body or 'data-reactroot' in body:
                report['technologies'].append('React')
            if 'express' in headers_str or 'connect.sid' in str(resp.cookies):
                report['technologies'].append('Express')
            if 'cloudflare' in headers_str:
                report['technologies'].append('Cloudflare')
            if 'django' in headers_str or 'csrftoken' in str(resp.cookies):
                report['technologies'].append('Django')

            report['technologies'] = list(set(report['technologies']))

            fuzz_paths = [
                '/.env', '/robots.txt', '/sitemap.xml', '/git/config',
                '/backup.zip', '/api/v1/users', '/swagger.ui', '/phpinfo.php',
                '/config.json', '/auth/login', '/graphql', '/debug', '/admin',
                '/server-status', '/xmlrpc.php', '/package.json', '/composer.json',
                '/api/v1/health', '/v2/swagger.json', '/metrics', '/actuator/env'
            ]

            base_origin = f"{urllib.parse.urlparse(target_url).scheme}://{urllib.parse.urlparse(target_url).netloc}"

            seen_paths = set()
            for path in fuzz_paths:
                if path in seen_paths:
                    continue
                seen_paths.add(path)
                test_url = base_origin + path
                try:
                    p_resp = session.get(test_url, timeout=3, verify=False)
                    if p_resp.status_code in [200, 403, 401]:
                        p_text = p_resp.text.lower()
                        if 'streamlit' in p_text and 'root' in p_text and len(p_text) > 500:
                            if abs(len(p_text) - len(base_homepage_text)) < 200:
                                continue
                        if p_resp.status_code == 200 and len(p_text) > 10:
                            if any(err in p_text for err in ["not found", "404 page", "does not exist", "object not found"]):
                                continue
                        report['exposed_files'].append({'path': path, 'status': p_resp.status_code, 'size': len(p_resp.text)})
                except Exception:
                    pass
        except ScopeViolation as e:
            report['error'] = f"Scope violation: {e}"
            report['blocked'] = True
        except Exception as e:
            report['error'] = str(e)
        return report


class AutonomousAgentExecutor:
    @staticmethod
    def _call_groq(messages: List[Dict[str, str]], groq_key: str, max_tokens: int = 1600, temperature: float = 0.4) -> str:
        headers = {'Authorization': f'Bearer {groq_key}', 'Content-Type': 'application/json'}
        full_text = ""
        convo = list(messages)
        for _ in range(2):
            payload = {
                'model': 'openai/gpt-oss-120b',
                'messages': convo,
                'temperature': temperature,
                'max_tokens': max_tokens,
            }
            resp = with_retry(requests.post, "https://api.groq.com/openai/v1/chat/completions",
                              json=payload, headers=headers, timeout=30)
            if resp.status_code != 200:
                return full_text + f"\n[AI Agent LLM Error: {resp.status_code} - {resp.text[:300]}]"
            choice = resp.json()['choices'][0]
            chunk = choice['message']['content']
            full_text += chunk
            if choice.get('finish_reason') != 'length':
                break
            convo = convo + [
                {'role': 'assistant', 'content': chunk},
                {'role': 'user', 'content': 'Continue exactly where you left off, no repetition.'}
            ]
        return full_text

    @staticmethod
    def run_agentic_cycle(target: str, groq_key: str) -> Dict[str, Any]:
        agent_log = []
        agent_log.append(f"[*] AI Agent initialized for autonomous target scope: {target}")

        recon_data = BugBountyReconEngine.deep_recon(target)
        if recon_data.get('blocked'):
            agent_log.append(f"[!] Recon blocked: {recon_data.get('error')}")
            return {
                'target': target, 'technologies': [], 'exposed_files': [],
                'agent_log': agent_log, 'ai_analysis': "Scan blocked by scope guard.",
                'blocked': True, 'block_reason': recon_data.get('error'),
            }
        agent_log.append(f"[+] Recon complete. Status: {recon_data.get('status_code')}, Server: {recon_data.get('server')}")

        technologies = recon_data.get('technologies', [])
        exposed = recon_data.get('exposed_files', [])
        agent_log.append(f"[+] Detected unique tech stack: {technologies}")
        agent_log.append(f"[+] Discovered valid exposed endpoints without duplicates: {len(exposed)}")

        subdomains = SubdomainEnumEngine.enumerate(target)
        agent_log.append(f"[+] Certificate-transparency subdomain enumeration found {len(subdomains)} host(s).")

        infra_audit = AdvancedReconEngine.audit_infrastructure(target)
        if infra_audit.get('blocked'):
            agent_log.append(f"[!] Infrastructure audit blocked: {infra_audit.get('error')}")
            infra_audit = {'ports': [], 'headers': {}}
        else:
            agent_log.append(f"[+] Infrastructure audit found {len(infra_audit.get('ports', []))} open port(s).")

        ai_analysis = "AI analysis skipped or key missing."
        if groq_key:
            prompt_context = f"""
            Target Scope: {target}
            Detected Technologies: {technologies}
            Exposed Sensitive Endpoints: {[e['path'] for e in exposed]}
            Enumerated Subdomains (sample): {subdomains[:15]}
            Please perform an authorized technical risk assessment, architectural vulnerability triage, and provide professional security hardening guidelines for these findings.
            """
            try:
                ai_analysis = AutonomousAgentExecutor._call_groq(
                    [
                        {'role': 'system', 'content': 'You are an authorized enterprise security engineer and bug bounty analyst performing authorized web application architecture assessment, vulnerability triage, and security hardening analysis.'},
                        {'role': 'user', 'content': prompt_context}
                    ],
                    groq_key, max_tokens=1600,
                )
                agent_log.append("[+] AI Agent successfully generated deep security context and hardening recommendations.")
            except Exception as e:
                ai_analysis = f"AI Agent connection exception: {e}"

        return {
            'target': target,
            'technologies': technologies,
            'exposed_files': exposed,
            'subdomains': subdomains,
            'infra_audit': infra_audit,
            'agent_log': agent_log,
            'ai_analysis': ai_analysis,
            'blocked': False,
        }


class NVDIntelligenceClient:
    VENDOR_ALLOWLIST = {
        "react": {"facebook", "reactjs", "react_project"},
        "express": {"expressjs", "openjs_foundation", "openjsf"},
        "cloudflare": {"cloudflare"},
        "django": {"djangoproject"},
        "laravel": {"laravel"},
        "wordpress": {"wordpress"},
    }

    def __init__(self, nvd_key: str = ""):
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.nvd_key = nvd_key

    @classmethod
    def _cpe_matches_keyword(cls, cve_item: Dict[str, Any], keyword: str) -> bool:
        kw = keyword.lower().strip()
        if not kw:
            return False
        allowed_vendors = cls.VENDOR_ALLOWLIST.get(kw)
        for config in cve_item.get('configurations', []):
            for node in config.get('nodes', []):
                for match in node.get('cpeMatch', []):
                    criteria = match.get('criteria', '').lower()
                    parts = criteria.split(':')
                    if len(parts) > 4:
                        vendor, product = parts[3], parts[4]
                        if allowed_vendors is not None:
                            if vendor in allowed_vendors and (kw == product or kw in product):
                                return True
                        else:
                            if kw == vendor or kw == product or kw in product:
                                return True
        return False

    def search_cve(self, keyword: str, max_results: int = 15, min_confidence: str = "any") -> List[VulnerabilityRecord]:
        vulnerabilities = []
        seen_cves = set()
        try:
            params = {'keywordSearch': keyword, 'resultsPerPage': min(max_results, 30)}
            headers = {'User-Agent': 'Naqaab50-Purple-Team-Suite/18.0 (+authorized-security-tooling)'}
            if self.nvd_key:
                headers['apiKey'] = self.nvd_key

            response = with_retry(requests.get, self.base_url, params=params, headers=headers, timeout=12)
            if response.status_code == 200:
                data = response.json()
                for item in data.get('vulnerabilities', []):
                    cve = item.get('cve', {})
                    cve_id = cve.get('id', 'UNKNOWN')

                    if cve_id in seen_cves:
                        continue
                    seen_cves.add(cve_id)

                    descriptions = cve.get('descriptions', [])
                    desc = descriptions[0].get('value', 'No description.') if descriptions else 'No description.'

                    score = 0.0
                    severity = "UNKNOWN"
                    vector = "N/A"
                    metrics = cve.get('metrics', {})

                    if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                        cvss_data = metrics['cvssMetricV31'][0].get('cvssData', {})
                        score = float(cvss_data.get('baseScore', 0.0))
                        severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                        vector = cvss_data.get('vectorString', 'N/A')
                    elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
                        cvss_data = metrics['cvssMetricV30'][0].get('cvssData', {})
                        score = float(cvss_data.get('baseScore', 0.0))
                        severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                        vector = cvss_data.get('vectorString', 'N/A')

                    if score < 4.0:
                        continue

                    confidence = "cpe" if self._cpe_matches_keyword(cve, keyword) else "keyword"
                    if min_confidence == "cpe" and confidence != "cpe":
                        continue

                    vulnerabilities.append(VulnerabilityRecord(
                        cve_id=cve_id,
                        title=cve_id,
                        description=desc,
                        severity=severity.upper(),
                        cvss_score=score,
                        vector_string=vector,
                        affected_configurations=[keyword],
                        published_date=str(cve.get('published', ''))[:10],
                        remediation=f"Apply official vendor patch or configure WAF signature to mitigate {cve_id}.",
                        match_confidence=confidence,
                    ))
        except Exception as e:
            logger.error(f"NVD API Error: {e}")
        return vulnerabilities


class ThreatIntelService:
    def __init__(self, vt_key: str, abuse_key: str, cache: Optional[TTLCache] = None):
        self.vt_key = vt_key
        self.abuse_key = abuse_key
        self.cache = cache

    def triage_indicator(self, indicator: str) -> Dict[str, Any]:
        cache_key = f"triage:{indicator}"
        if self.cache:
            cached = self.cache.get(cache_key)
            if cached:
                return cached

        results = {
            'indicator': indicator,
            'vt_raw': None,
            'vt_summary': {'malicious': 0, 'suspicious': 0, 'harmless': 0, 'undetected': 0, 'reputation': 0, 'tags': [], 'registrar': 'N/A'},
            'abuse_raw': None,
            'abuse_summary': {'score': 0, 'reports': 0, 'country': 'N/A', 'isp': 'N/A', 'lastReported': 'N/A'}
        }

        try:
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

                    resp = with_retry(requests.get, url, headers=headers, timeout=10)
                    if resp.status_code == 200:
                        vt_json = resp.json()
                        results['vt_raw'] = vt_json
                        attrs = vt_json.get('data', {}).get('attributes', {})
                        stats = attrs.get('last_analysis_stats', {})

                        results['vt_summary']['malicious'] = int(stats.get('malicious', 0))
                        results['vt_summary']['suspicious'] = int(stats.get('suspicious', 0))
                        results['vt_summary']['harmless'] = int(stats.get('harmless', 0))
                        results['vt_summary']['undetected'] = int(stats.get('undetected', 0))
                        results['vt_summary']['reputation'] = int(attrs.get('reputation', 0))
                        results['vt_summary']['tags'] = list(set(attrs.get('tags', [])))
                        results['vt_summary']['registrar'] = attrs.get('registrar', attrs.get('as_owner', 'N/A'))
                    else:
                        results['vt_summary']['error'] = f"VT HTTP Status: {resp.status_code}"
                except Exception as e:
                    results['vt_summary']['error'] = str(e)

            if self.abuse_key and is_ip:
                try:
                    headers = {'Key': self.abuse_key, 'Accept': 'application/json'}
                    params = {'ipAddress': indicator, 'maxAgeInDays': 90, 'verbose': True}
                    resp = with_retry(requests.get, "https://api.abuseipdb.com/api/v2/check",
                                      headers=headers, params=params, timeout=10)
                    if resp.status_code == 200:
                        abuse_json = resp.json()
                        results['abuse_raw'] = abuse_json
                        data = abuse_json.get('data', {})

                        results['abuse_summary']['score'] = int(data.get('abuseConfidenceScore', 0))
                        results['abuse_summary']['reports'] = int(data.get('totalReports', 0))
                        results['abuse_summary']['country'] = str(data.get('countryCode', 'N/A'))
                        results['abuse_summary']['isp'] = str(data.get('isp', 'N/A'))
                        results['abuse_summary']['lastReported'] = str(data.get('lastReportedAt', 'Never'))
                    else:
                        results['abuse_summary']['error'] = f"AbuseIPDB Status: {resp.status_code}"
                except Exception as e:
                    results['abuse_summary']['error'] = str(e)
        except Exception as e:
            logger.error(f"ThreatIntel error: {e}")

        if self.cache:
            self.cache.set(cache_key, results)
        return results


class AdvancedReconEngine:
    @staticmethod
    def audit_infrastructure(domain: str) -> Dict[str, Any]:
        report = {'dns': {}, 'ports': [], 'ssl': {'valid': False}, 'headers': {}}
        try:
            clean_domain = domain.replace('https://', '').replace('http://', '').split('/')[0]
            assert_public_host(clean_domain)

            for rtype in ['A', 'AAAA', 'MX', 'TXT', 'NS', 'SOA']:
                try:
                    answers = dns.resolver.resolve(clean_domain, rtype)
                    report['dns'][rtype] = list(set([str(r) for r in answers]))
                except Exception:
                    report['dns'][rtype] = []

            common_ports = [21, 22, 25, 53, 80, 110, 443, 445, 1433, 3306, 3389, 5432, 8080, 8443, 9200]
            open_ports = []
            seen_ports = set()

            def scan_port(port):
                if port in seen_ports:
                    return None
                seen_ports.add(port)
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.8)
                    res = sock.connect_ex((clean_domain, port))
                    sock.close()
                    if res == 0:
                        sname = {
                            21: 'FTP', 22: 'SSH', 25: 'SMTP', 53: 'DNS', 80: 'HTTP',
                            110: 'POP3', 443: 'HTTPS', 445: 'SMB', 1433: 'MSSQL',
                            3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 8080: 'HTTP-Alt',
                            8443: 'HTTPS-Alt', 9200: 'Elasticsearch'
                        }.get(port, 'Unknown')
                        return {'port': port, 'service': sname, 'status': 'OPEN'}
                except Exception:
                    pass
                return None

            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                futures = [executor.submit(scan_port, p) for p in common_ports]
                for f in concurrent.futures.as_completed(futures):
                    res = f.result()
                    if res:
                        open_ports.append(res)
            report['ports'] = sorted(open_ports, key=lambda x: x['port'])

            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with socket.create_connection((clean_domain, 443), timeout=3) as sock:
                    with ctx.wrap_socket(sock, server_hostname=clean_domain) as ssock:
                        cert = ssock.getpeercert()
                        if cert:
                            report['ssl']['valid'] = True
                            report['ssl']['details'] = {
                                'subject': dict(x[0] for x in cert.get('subject', [])),
                                'issuer': dict(x[0] for x in cert.get('issuer', [])),
                                'version': cert.get('version'),
                                'not_before': cert.get('notBefore'),
                                'not_after': cert.get('notAfter')
                            }
            except Exception as e:
                report['ssl']['error'] = str(e)

            try:
                resp = with_retry(requests.get, f"https://{clean_domain}", timeout=5, verify=False)
                target_headers = ['Strict-Transport-Security', 'Content-Security-Policy', 'X-Frame-Options', 'X-Content-Type-Options', 'X-XSS-Protection']
                for h in target_headers:
                    report['headers'][h] = resp.headers.get(h, 'MISSING')
            except Exception as e:
                report['headers']['error'] = str(e)
        except ScopeViolation as e:
            report['error'] = f"Scope violation: {e}"
            report['blocked'] = True
        except Exception as e:
            logger.error(f"Audit error: {e}")
            report['error'] = str(e)
        return report


# ═══════════════════════════════════════════════════════════════════════════════
# 3. STREAMLIT HACKER TERMINAL UI & OAUTH HANDLER
# ═══════════════════════════════════════════════════════════════════════════════

def authorization_gate(key_suffix: str) -> bool:
    return st.checkbox(
        "I confirm I am authorized to test this target (owner, bug-bounty program scope, or written permission).",
        key=f"authz_{key_suffix}",
    )


def main():
    st.set_page_config(
        page_title="Naqaab50 // Elite Security Operations Suite",
        page_icon="💀",
        layout="wide",
        initial_sidebar_state="expanded"
    )

    st.markdown("""
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Inter:wght@400;600&display=swap');

        .stApp {
            background-color: #020408;
            color: #00ff66;
            font-family: 'Share Tech Mono', monospace, sans-serif;
        }
        
        [data-testid="stSidebar"] {
            background-color: #050b14;
            border-right: 1px solid rgba(0, 255, 102, 0.2);
        }
        
        .saas-card {
            background: rgba(5, 11, 20, 0.85);
            border: 1px solid rgba(0, 255, 102, 0.3);
            border-radius: 4px;
            padding: 20px;
            backdrop-filter: blur(12px);
            margin-bottom: 16px;
            box-shadow: 0 0 15px rgba(0, 255, 102, 0.05);
        }
        
        .stButton>button {
            background: linear-gradient(135deg, #001105 0%, #003311 100%);
            color: #00ff66;
            border: 1px solid #00ff66;
            border-radius: 4px;
            font-family: 'Share Tech Mono', monospace;
            font-weight: 600;
            padding: 0.5rem 1rem;
            transition: all 0.3s ease;
            box-shadow: 0 0 10px rgba(0, 255, 102, 0.2);
        }
        .stButton>button:hover {
            background: #00ff66;
            color: #020408;
            box-shadow: 0 0 20px rgba(0, 255, 102, 0.6);
            transform: translateY(-1px);
        }
        .stButton>button:disabled {
            opacity: 0.4;
            box-shadow: none;
            transform: none;
        }
        
        [data-testid="stMetric"] {
            background: rgba(5, 11, 20, 0.9);
            border: 1px solid rgba(0, 229, 255, 0.3);
            padding: 16px;
            border-radius: 4px;
            box-shadow: 0 0 10px rgba(0, 229, 255, 0.1);
        }
        [data-testid="stMetricLabel"] {
            color: #00e5ff !important;
            font-family: 'Share Tech Mono', monospace;
        }
        [data-testid="stMetricValue"] {
            color: #00ff66 !important;
            font-family: 'Share Tech Mono', monospace;
        }
        
        .stTextInput>div>div>input, .stTextArea>div>div>textarea {
            background-color: #050b14;
            color: #00ff66;
            border: 1px solid #00ff6644;
            border-radius: 4px;
            font-family: 'Share Tech Mono', monospace;
        }
        .stTextInput>div>div>input:focus, .stTextArea>div>div>textarea:focus {
            border-color: #00ff66;
            box-shadow: 0 0 10px rgba(0, 255, 102, 0.4);
        }
        
        h1, h2, h3 {
            color: #00ff66;
            font-family: 'Share Tech Mono', monospace;
            letter-spacing: 0.05em;
            text-shadow: 0 0 8px rgba(0, 255, 102, 0.3);
        }
        p, label, span {
            color: #a0aec0;
            font-family: 'Share Tech Mono', monospace;
        }
        </style>
    """, unsafe_allow_html=True)

    db = SecurityDatabase()

    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    if 'login_attempts' not in st.session_state:
        st.session_state.login_attempts = 0
    if 'login_locked_until' not in st.session_state:
        st.session_state.login_locked_until = 0.0

    # Session states for Email OTP Verification during registration
    if 'reg_otp_sent' not in st.session_state:
        st.session_state.reg_otp_sent = False
    if 'reg_temp_email' not in st.session_state:
        st.session_state.reg_temp_email = ""
    if 'reg_temp_pass' not in st.session_state:
        st.session_state.reg_temp_pass = ""
    if 'reg_generated_otp' not in st.session_state:
        st.session_state.reg_generated_otp = ""

    # Real Google OAuth Callback Handler with direct fallback support
    query_params = st.query_params
    if "code" in query_params and not st.session_state.authenticated:
        code = query_params["code"]
        google_client_id = "763689681371-todpc6sgvbcodsntaiunbdcii2a037f8.apps.googleusercontent.com"
        google_client_secret = "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"
        try:
            google_client_id = st.secrets.get("GOOGLE_CLIENT_ID", google_client_id)
            google_client_secret = st.secrets.get("GOOGLE_CLIENT_SECRET", google_client_secret)
        except Exception:
            pass
        redirect_uri = "https://naqb50.streamlit.app/"

        if google_client_id and google_client_secret:
            token_url = "https://oauth2.googleapis.com/token"
            payload = {
                "code": code,
                "client_id": google_client_id,
                "client_secret": google_client_secret,
                "redirect_uri": redirect_uri,
                "grant_type": "authorization_code"
            }
            try:
                token_resp = requests.post(token_url, data=payload)
                if token_resp.status_code == 200:
                    access_token = token_resp.json().get("access_token")
                    userinfo_resp = requests.get("https://www.googleapis.com/oauth2/v3/userinfo", headers={"Authorization": f"Bearer {access_token}"})
                    if userinfo_resp.status_code == 200:
                        user_email = userinfo_resp.json().get("email")
                        st.session_state.authenticated = True
                        st.session_state.user = user_email
                        st.query_params.clear()
                        st.rerun()
            except Exception as e:
                st.error(f"Google OAuth token exchange failed: {e}")

    if not st.session_state.authenticated:
        col1, col2, col3 = st.columns([1, 1.2, 1])
        with col2:
            st.markdown("<br><br>", unsafe_allow_html=True)
            st.markdown("""
                <div class="saas-card" style="text-align: center;">
                    <h2>// NAQAAB50 TERMINAL GATEWAY</h2>
                    <p style="color: #00e5ff;">Autonomous Elite Security Operations Suite</p>
                </div>
            """, unsafe_allow_html=True)

            auth_mode = st.radio("Access Mode", ["Sign In", "Create Account", "Google Continue (SSO)"], horizontal=True)

            if auth_mode == "Sign In":
                username = st.text_input("Operator Email / Identifier")
                password = st.text_input("Encryption Key / Password", type="password")

                if st.button("Authenticate Suite", use_container_width=True):
                    correct_user = st.secrets.get("APP_USERNAME", "naqaab")
                    correct_pass = st.secrets.get("APP_PASSWORD", "root50")
                    user_ok = hmac.compare_digest(username, correct_user)
                    pass_ok = hmac.compare_digest(password, correct_pass)
                    
                    if (user_ok and pass_ok) or db.verify_user(username, password):
                        st.session_state.authenticated = True
                        st.session_state.user = username
                        st.session_state.login_attempts = 0
                        st.success("Authentication successful. Decrypting operational modules...")
                        st.rerun()
                    else:
                        st.session_state.login_attempts += 1
                        if st.session_state.login_attempts >= 5:
                            st.session_state.login_locked_until = time.time() + 60
                            st.session_state.login_attempts = 0
                            st.error("Too many failed credentials attempts. Locked for 60 seconds.")
                        else:
                            st.error("Access Denied: Invalid credentials.")

            elif auth_mode == "Create Account":
                if not st.session_state.reg_otp_sent:
                    new_email = st.text_input("New Operator Email")
                    new_pass = st.text_input("Choose Secure Password", type="password")

                    if st.button("Send Verification Code", use_container_width=True):
                        if len(new_email) > 3 and len(new_pass) >= 6:
                            otp = str(random.randint(100000, 999999))
                            st.session_state.reg_generated_otp = otp
                            st.session_state.reg_temp_email = new_email
                            st.session_state.reg_temp_pass = new_pass

                            if send_otp_email(new_email, otp):
                                st.session_state.reg_otp_sent = True
                                st.success("Verification code email par bhej diya gaya hai!")
                                st.rerun()
                            else:
                                st.error("Email dispatch karne mein masla aaya. SMTP configuration check karein.")
                        else:
                            st.warning("Please enter a valid email and a password of at least 6 characters.")
                else:
                    st.info(f"Verification code sent to `{st.session_state.reg_temp_email}`")
                    entered_otp = st.text_input("Enter 6-Digit Verification Code")

                    col_otp1, col_otp2 = st.columns(2)
                    with col_otp1:
                        if st.button("Verify & Register", use_container_width=True):
                            if entered_otp.strip() == st.session_state.reg_generated_otp:
                                if db.create_user(st.session_state.reg_temp_email, st.session_state.reg_temp_pass):
                                    st.success("Account successfully verified and registered! Please switch to 'Sign In' to access your console.")
                                    st.session_state.reg_otp_sent = False
                                    st.session_state.reg_generated_otp = ""
                                    st.session_state.reg_temp_email = ""
                                    st.session_state.reg_temp_pass = ""
                                    st.rerun()
                                else:
                                    st.error("Registration failed: Email already registered in SQLite database.")
                            else:
                                st.error("Ghalat OTP code! Dobara check karein.")
                    with col_otp2:
                        if st.button("Cancel / Retry", use_container_width=True):
                            st.session_state.reg_otp_sent = False
                            st.rerun()

            else:
                st.markdown("<p style='text-align: center; color: #a0aec0;'>Authenticate securely using official Google workspace credentials.</p>", unsafe_allow_html=True)
                client_id = "763689681371-todpc6sgvbcodsntaiunbdcii2a037f8.apps.googleusercontent.com"
                try:
                    client_id = st.secrets.get("GOOGLE_CLIENT_ID", client_id)
                except Exception:
                    pass
                redirect_uri = "https://naqb50.streamlit.app/"

                if client_id:
                    google_auth_url = f"https://accounts.google.com/o/oauth2/v2/auth?response_type=code&client_id={client_id}&redirect_uri={urllib.parse.quote(redirect_uri)}&scope=openid%20email%20profile"
                    st.markdown(f'<a href="{google_auth_url}" target="_self"><button style="width:100%; background:#001105; color:#00ff66; border:1px solid #00ff66; padding:10px; border-radius:4px; font-family:\'Share Tech Mono\'; font-weight:600; cursor:pointer; box-shadow:0 0 10px rgba(0,255,102,0.2);">Continue with Google Workspace</button></a>', unsafe_allow_html=True)
                else:
                    st.info("Google Client ID missing in secrets. Falling back to simulator mode:")
                    if st.button("Simulate Google Login", use_container_width=True):
                        st.session_state.authenticated = True
                        st.session_state.user = st.secrets.get("DEFAULT_GOOGLE_USER", "operator.naqaab@gmail.com")
                        st.success("Google handshake verified.")
                        st.rerun()
        return

    session_timeout_minutes = int(st.secrets.get("SESSION_TIMEOUT_MINUTES", DEFAULT_SESSION_TIMEOUT_MINUTES))
    if not enforce_session_timeout(session_timeout_minutes):
        return

    max_scans_per_day = int(st.secrets.get("MAX_ACTIVE_SCANS_PER_DAY", DEFAULT_MAX_ACTIVE_SCANS_PER_DAY))

    # Retrieve current operator's personal stored API keys from SQLite database vault
    saved_keys = db.get_user_keys(st.session_state.user)

    vt_key = saved_keys["vt"] or st.secrets.get("VIRUSTOTAL_API_KEY", "")
    abuse_key = saved_keys["abuse"] or st.secrets.get("ABUSEIPDB_API_KEY", "")
    groq_key = saved_keys["groq"] or st.secrets.get("GROQ_API_KEY", "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")
    nvd_key = saved_keys["nvd"] or st.secrets.get("NVD_API_KEY", "")
    shared_cache = get_shared_cache()

    with st.sidebar:
        st.markdown(f"### [OPERATOR] `{st.session_state.user}`")
        st.markdown("---")
        module = st.radio(
            "NAQAAB50 OPERATIONS MENU",
            [
                "Command Telemetry Center",
                "Personal API Key Vault",
                "Autonomous AI-Agent Red/Blue Pipeline",
                "AI Security Chatbot",
                "Blue Team SOC Log & SIEM Simulator",
                "Automated Sigma Rule Generator",
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

    if module == "Command Telemetry Center":
        st.markdown("# // COMMAND TELEMETRY CENTER")
        st.markdown("<p style='color: #a0aec0;'>Aggregated telemetry across offensive recon and defensive SIEM monitoring.</p>", unsafe_allow_html=True)

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Threat Concode", "LEVEL 5", "Critical")
        c2.metric("NVD Client", "Accelerated" if nvd_key else "Standard", "NIST v2.0")
        c3.metric("Groq AI Engine", "Online" if groq_key else "Offline", "openai/gpt-oss-120b")
        c4.metric("Encrypted DB", "Connected", "Active")

    elif module == "Personal API Key Vault":
        st.markdown("# // PERSONAL API KEY VAULT")
        st.markdown("<p style='color: #a0aec0;'>Configure and save your personal API keys securely into your account database vault. These will persist across sessions.</p>", unsafe_allow_html=True)

        with st.form("api_vault_form"):
            p_vt = st.text_input("VirusTotal API Key", value=saved_keys["vt"], type="password")
            p_abuse = st.text_input("AbuseIPDB API Key", value=saved_keys["abuse"], type="password")
            p_groq = st.text_input("Groq AI API Key", value=saved_keys["groq"], type="password")
            p_nvd = st.text_input("NIST NVD API Key", value=saved_keys["nvd"], type="password")
            
            saved = st.form_submit_button("Save Keys to Account Vault", use_container_width=True)
            if saved:
                db.update_user_keys(st.session_state.user, p_vt, p_abuse, p_groq, p_nvd)
                st.success("API keys successfully saved to your account vault!")
                st.rerun()

    elif module == "Autonomous AI-Agent Red/Blue Pipeline":
        st.markdown("# // FULLY AUTONOMOUS PURPLE TEAM PIPELINE")
        st.markdown("<p style='color: #a0aec0;'>Enter target scope. The AI Agent executes live multi-API recon, threat triage, soft-404 filtered fuzzing, NVD vulnerability correlation, and unified architectural hardening guidance.</p>", unsafe_allow_html=True)

        pipeline_target = st.text_input("Target Domain, IP Address, or Keyword", placeholder="e.g., target-domain.com or 8.8.8.8")
        strict_cve = st.checkbox("Strict CVE matching (CPE-confirmed only — fewer false positives)", value=True)
        authorized = authorization_gate("pipeline")

        if st.button("Execute Autonomous Campaign", use_container_width=True, disabled=not authorized):
            validation_error = validate_target_input(pipeline_target) if pipeline_target else "Please specify a target for the autonomous agent."
            quota_error = None
            if not validation_error:
                quota_error = check_and_increment_scan_quota(st.session_state.user, max_scans_per_day)

            if quota_error:
                st.error(quota_error)
            elif validation_error:
                st.warning(validation_error)
            else:
                with st.spinner("Autonomous AI Agent taking full control: running deep recon and deduplication loops..."):
                    agent_result = AutonomousAgentExecutor.run_agentic_cycle(pipeline_target, groq_key)

                    if agent_result.get('blocked'):
                        st.error(f"Scan blocked by scope guard: {agent_result.get('block_reason')}")
                    else:
                        ti = ThreatIntelService(vt_key, abuse_key, cache=shared_cache)
                        ti_res = ti.triage_indicator(pipeline_target)

                        clean_target = pipeline_target.replace('https://', '').replace('http://', '').split('/')[0]
                        domain_keyword = clean_target.split('.')[0] if '.' in clean_target else clean_target

                        tech_stack = agent_result.get('technologies', [])
                        AMBIGUOUS_GENERIC_TECH = {"react", "express", "cloudflare"}
                        specific_techs = [t for t in tech_stack if t.lower() not in AMBIGUOUS_GENERIC_TECH]
                        nvd_query_term = specific_techs[0] if specific_techs else domain_keyword

                        nvd = NVDIntelligenceClient(nvd_key)
                        min_conf = "cpe" if strict_cve else "any"
                        cve_res = nvd.search_cve(nvd_query_term, max_results=8, min_confidence=min_conf)
                        if not cve_res and domain_keyword != nvd_query_term:
                            cve_res = nvd.search_cve(domain_keyword, max_results=8, min_confidence=min_conf)

                        st.success("Autonomous AI Agent execution cycle successfully completed.")

                        top_cvss = max([v.cvss_score for v in cve_res], default=0.0)
                        infra_audit = agent_result.get('infra_audit', {}) or {}
                        exposed_count = len(agent_result.get('exposed_files', []))
                        missing_headers = sum(
                            1 for v in infra_audit.get('headers', {}).values() if v == 'MISSING'
                        )
                        risky_ports = sum(
                            1 for p in infra_audit.get('ports', [])
                            if p.get('port') in RISKY_PUBLIC_PORTS
                        )

                        risk = compute_risk_score(
                            ti_res['vt_summary']['malicious'],
                            ti_res['abuse_summary']['score'],
                            top_cvss,
                            exposed_count=exposed_count,
                            missing_headers=missing_headers,
                            risky_open_ports=risky_ports,
                        )

                        c1, c2, c3, c4 = st.columns(4)
                        c1.metric("VT Malicious Detections", ti_res['vt_summary']['malicious'])
                        c2.metric("Abuse Confidence Score", f"{ti_res['abuse_summary']['score']}%")
                        c3.metric("Deduplicated Unique CVEs", len(cve_res))
                        c4.metric("Aggregate Risk Score", f"{risk['score']}/100", risk['band'])

                        with st.expander("🤖 View Live Autonomous Agent Execution Logs"):
                            for log_line in agent_result.get('agent_log', []):
                                st.code(log_line)

                        subdomains = agent_result.get('subdomains', [])
                        if subdomains:
                            with st.expander(f"🌐 Enumerated Subdomains ({len(subdomains)})"):
                                st.dataframe(pd.DataFrame({'subdomain': subdomains}), use_container_width=True)

                        if infra_audit.get('ports') or infra_audit.get('headers'):
                            with st.expander("🔍 Infrastructure Findings (Ports & Security Headers)"):
                                if infra_audit.get('ports'):
                                    st.markdown("**Open Ports:**")
                                    st.dataframe(pd.DataFrame(infra_audit['ports']), use_container_width=True)
                                if infra_audit.get('headers') and 'error' not in infra_audit['headers']:
                                    st.markdown("**Security Headers:**")
                                    for h_name, h_val in infra_audit['headers'].items():
                                        icon = "❌" if h_val == 'MISSING' else "✅"
                                        st.write(f"{icon} **{h_name}:** `{h_val}`")

                        ai_analysis_text = agent_result.get('ai_analysis', "AI analysis skipped.")

                        cve_list_md = "\n".join([
                            f"- **{v.cve_id}** (CVSS: {v.cvss_score} - {v.severity}, match: {v.match_confidence}): {v.description}"
                            for v in cve_res
                        ]) if cve_res else "No high-severity matching CVE entries found."
                        exposed_md = "\n".join([f"- Endpoint: `{ef['path']}` | Status: `{ef['status']}`" for ef in agent_result.get('exposed_files', [])]) if agent_result.get('exposed_files') else "No sensitive endpoints exposed on standard fuzz paths."
                        subdomain_md = "\n".join([f"- `{s}`" for s in subdomains[:30]]) if subdomains else "None discovered via certificate transparency logs."
                        tech_md = ", ".join(tech_stack) if tech_stack else "Custom / Undetected"
                        ports_md = "\n".join([f"- `{p['port']}` ({p['service']})" for p in infra_audit.get('ports', [])]) if infra_audit.get('ports') else "No open ports found on scanned standard ports."
                        headers_md = "\n".join([
                            f"- **{h}:** `{v}`" for h, v in infra_audit.get('headers', {}).items() if h != 'error'
                        ]) if infra_audit.get('headers') else "Not assessed."

                        report_data = {
                            "target": pipeline_target,
                            "operator": st.session_state.user,
                            "timestamp": datetime.now().isoformat(),
                            "risk_score": risk,
                            "threat_intel": ti_res['vt_summary'] | {"abuse": ti_res['abuse_summary']},
                            "technologies": tech_stack,
                            "exposed_files": agent_result.get('exposed_files', []),
                            "subdomains": subdomains,
                            "infra_ports": infra_audit.get('ports', []),
                            "infra_headers": infra_audit.get('headers', {}),
                            "cves": [v.to_dict() for v in cve_res],
                            "ai_analysis": ai_analysis_text,
                        }

                        auto_report_markdown = f"""# NAQAAB50 SECURITY ASSESSMENT REPORT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
* **Target Scope:** `{pipeline_target}`
* **Lead Operator:** `{st.session_state.user} (Naqaab50 AI Engine)`
* **Timestamp:** `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`
* **Aggregate Risk Score:** `{risk['score']}/100 ({risk['band']})`
* **Classification:** RESTRICTED // Eℓite RED/BLUE INTEL

## 1. Executive Summary & Recon Scope Overview
Automated security intelligence gathering was completed against `{pipeline_target}`.
- **VirusTotal Malicious Count:** `{ti_res['vt_summary']['malicious']}`
- **AbuseIPDB Score:** `{ti_res['abuse_summary']['score']}%`
- **Detected Technologies:** `{tech_md}`

## 2. Threat Intelligence & Reputation Triage
### VirusTotal Telemetry
- **Harmless Engines:** `{ti_res['vt_summary']['harmless']}`
- **Community Reputation:** `{ti_res['vt_summary']['reputation']}`
- **ASN / Owner:** `{ti_res['vt_summary']['registrar']}`

### AbuseIPDB Telemetry
- **Reports Count:** `{ti_res['abuse_summary']['reports']}`
- **Country Code:** `{ti_res['abuse_summary']['country']}`
- **ISP:** `{ti_res['abuse_summary']['isp']}`

## 3. Attack Surface Discovery & Exposed Endpoints
- **Discovered Endpoints & Files:**
{exposed_md}

### Enumerated Subdomains
{subdomain_md}

### Open Ports
{ports_md}

### Security Headers
{headers_md}

## 4. Correlated Vulnerabilities (NIST NVD v2.0 - Filtered CVSS >= 4.0)
{cve_list_md}

## 5. Unified Purple Team Architectural Analysis & Hardening Recommendations
{ai_analysis_text}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
*Generated via Naqaab50 Elite Security Operations Suite*
"""

                        st.markdown("---")
                        st.markdown("### Generated Security Report Preview")
                        st.markdown(auto_report_markdown)

                        dl1, dl2, dl3 = st.columns(3)
                        with dl1:
                            st.download_button(
                                label="Download Report (.md)",
                                data=auto_report_markdown,
                                file_name=f"naqaab50_report_{pipeline_target.replace('/', '_')}.md",
                                mime="text/markdown",
                                use_container_width=True
                            )
                        with dl2:
                            st.download_button(
                                label="Download Report (.json)",
                                data=json.dumps(report_data, indent=2, default=str),
                                file_name=f"naqaab50_report_{pipeline_target.replace('/', '_')}.json",
                                mime="application/json",
                                use_container_width=True
                            )
                        with dl3:
                            cve_csv = pd.DataFrame([v.to_dict() for v in cve_res]).to_csv(index=False) if cve_res else "cve_id,severity,cvss_score\n"
                            st.download_button(
                                label="Download CVE Findings (.csv)",
                                data=cve_csv,
                                file_name=f"naqaab50_cve_{pipeline_target.replace('/', '_')}.csv",
                                mime="text/csv",
                                use_container_width=True
                            )
        elif not authorized:
            st.caption("Check authorization box above to execute active campaign.")

    elif module == "AI Security Chatbot":
        st.markdown("# // SEC_AI OPERATIONS CHATBOT")
        st.markdown("<p style='color: #a0aec0;'>Ask anything about security, exploit vectors, WAF bypass, or defense strategies. Powered by Groq AI.</p>", unsafe_allow_html=True)

        if "messages" not in st.session_state:
            st.session_state.messages = [
                {"role": "assistant", "content": "Naqaab50 neural link active. State your directive, operator."}
            ]

        for message in st.session_state.messages:
            with st.chat_message(message["role"]):
                st.markdown(message["content"])

        if prompt := st.chat_input("Ask a security query or request a playbook..."):
            st.session_state.messages.append({"role": "user", "content": prompt})
            with st.chat_message("user"):
                st.markdown(prompt)

            with st.chat_message("assistant"):
                if not groq_key:
                    response_text = "Error: Groq API Key is not configured. Please add it in your **Personal API Key Vault**."
                    st.markdown(response_text)
                else:
                    with st.spinner("Processing neural query via Groq AI..."):
                        try:
                            response_text = AutonomousAgentExecutor._call_groq(
                                [
                                    {'role': 'system', 'content': 'You are Naqaab50 AI, an elite Cybersecurity Expert, Purple Team Mentor, and Red/Blue Team Advisor specializing in security assessments.'},
                                    *[{'role': m['role'], 'content': m['content']} for m in st.session_state.messages]
                                ],
                                groq_key, max_tokens=1500, temperature=0.6,
                            )
                        except Exception as e:
                            response_text = f"Connection failed: {e}"
                        st.markdown(response_text)
                st.session_state.messages.append({"role": "assistant", "content": response_text})

    elif module == "Blue Team SOC Log & SIEM Simulator":
        st.markdown("# // SOC LOG PARSING & ANOMALY DETECTOR")
        st.markdown("<p style='color: #a0aec0;'>Paste raw server access logs or Windows Event logs below to simulate SIEM parsing and anomaly detection.</p>", unsafe_allow_html=True)

        sample_log = st.text_area("Raw Log Data Input", placeholder="Paste Apache/Nginx access log or Windows Event log lines here...", height=150)

        if st.button("Analyze Logs & Detect Anomalies", use_container_width=True):
            if sample_log:
                with st.spinner("Running heuristic parsing and threat detection..."):
                    st.success("Log parsing complete.")

                    lines = [l.strip() for l in sample_log.split('\n') if l.strip()]
                    suspicious_hits = []
                    for idx, line in enumerate(lines, 1):
                        l_lower = line.lower()
                        if any(k in l_lower for k in ['union select', '<script>', 'etc/passwd', 'cmd.exe', '/wpscan', 'sqlmap', 'eval(']):
                            suspicious_hits.append({'line_no': idx, 'content': line, 'indicator': 'Injection / Exploit Pattern'})
                        elif '404' in line or '403' in line:
                            suspicious_hits.append({'line_no': idx, 'content': line, 'indicator': 'Unauthorized / Failed Request'})

                    c1, c2 = st.columns(2)
                    c1.metric("Total Log Lines Analyzed", len(lines))
                    c2.metric("Detected Anomalies / Hits", len(suspicious_hits))

                    if suspicious_hits:
                        st.markdown("### Detected Security Anomalies")
                        st.dataframe(pd.DataFrame(suspicious_hits), use_container_width=True)
                    else:
                        st.info("No malicious patterns or obvious anomalies detected in the provided log sample.")
            else:
                st.warning("Please paste some log data to analyze.")

    elif module == "Automated Sigma Rule Generator":
        st.markdown("# // SIGMA & YARA DETECTION GENERATOR")
        st.markdown("<p style='color: #a0aec0;'>Generate production-ready SIEM detection rules for any CVE, IoC, or attack pattern using Groq AI.</p>", unsafe_allow_html=True)

        cve_input = st.text_input("Enter CVE ID or Attack Description", placeholder="e.g., CVE-2021-44228 or Path Traversal Attack")
        if st.button("Generate Sigma Detection Rule", use_container_width=True):
            if cve_input:
                if not groq_key:
                    st.error("Groq API Key is missing. Add it in your **Personal API Key Vault**.")
                else:
                    with st.spinner("Generating professional Sigma detection rule via Groq AI..."):
                        try:
                            sigma_res = AutonomousAgentExecutor._call_groq(
                                [
                                    {'role': 'system', 'content': 'You are a senior Blue Team threat hunter. Generate a valid, production-ready Sigma detection rule in YAML format for the requested vulnerability or threat vector.'},
                                    {'role': 'user', 'content': f"Generate a Sigma rule for: {cve_input}"}
                                ],
                                groq_key, max_tokens=1000, temperature=0.3,
                            )
                            st.code(sigma_res, language='yaml')
                        except Exception as e:
                            st.error(f"Error: {e}")
            else:
                st.warning("Please enter a CVE ID or attack description.")

    elif module == "Bug Bounty Recon & Fuzzing":
        st.markdown("# // RECON & ENDPOINT FUZZER")
        target_input = st.text_input("Target URL or Domain", placeholder="e.g., target-domain.com")
        include_subdomains = st.checkbox("Also enumerate subdomains (crt.sh)", value=True)
        authorized = authorization_gate("recon")

        if st.button("Launch Recon & Asset Discovery", use_container_width=True, disabled=not authorized):
            validation_error = validate_target_input(target_input) if target_input else "Please specify a target."
            if validation_error:
                st.warning(validation_error)
            else:
                with st.spinner(f"Executing deep offensive reconnaissance on {target_input}..."):
                    recon = BugBountyReconEngine.deep_recon(target_input)
                    db.log_activity("Bug Bounty Recon", target_input, "Completed")

                    if recon.get('blocked'):
                        st.error(f"Scan blocked by scope guard: {recon.get('error')}")
                    else:
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
                        else:
                            st.info("No common sensitive files discovered on standard paths.")

                        if include_subdomains:
                            st.markdown("### Enumerated Subdomains (Certificate Transparency)")
                            subs = SubdomainEnumEngine.enumerate(target_input)
                            if subs:
                                st.dataframe(pd.DataFrame({'subdomain': subs}), use_container_width=True)
                            else:
                                st.info("No subdomains found via crt.sh.")
        elif not authorized:
            st.caption("Check authorization box above to execute recon.")

    elif module == "Network Infrastructure Audit":
        st.markdown("# // INFRASTRUCTURE AUDIT")
        target_domain = st.text_input("Target Domain or IP Address", placeholder="e.g., scanme.nmap.org")
        authorized = authorization_gate("audit")

        if st.button("Execute Full Infrastructure Audit", use_container_width=True, disabled=not authorized):
            validation_error = validate_target_input(target_domain, allow_url=False) if target_domain else "Please provide a valid target host."
            if validation_error:
                st.warning(validation_error)
            else:
                with st.spinner(f"Executing live infrastructure audit against {target_domain}..."):
                    audit_data = AdvancedReconEngine.audit_infrastructure(target_domain)
                    db.log_activity("Infrastructure Audit", target_domain, "Completed")

                    if audit_data.get('blocked'):
                        st.error(f"Scan blocked by scope guard: {audit_data.get('error')}")
                    else:
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
        elif not authorized:
            st.caption("Check authorization box above to execute audit.")

    elif module == "Enterprise NVD Intelligence":
        st.markdown("# // NVD VULNERABILITY INTELLIGENCE")
        keyword = st.text_input("Search Software / Vendor / CVE", placeholder="e.g., apache, wordpress plugin, cve-2024")
        strict_cve = st.checkbox("Strict CVE matching (CPE-confirmed only)", value=False)

        if st.button("Query NVD Database", use_container_width=True):
            if keyword:
                with st.spinner("Fetching CVE telemetry from NIST NVD..."):
                    client = NVDIntelligenceClient(nvd_key)
                    vulns = client.search_cve(keyword, min_confidence="cpe" if strict_cve else "any")
                    db.log_activity("NVD Research", keyword, f"Found {len(vulns)} CVEs")

                    if vulns:
                        st.success(f"Retrieved {len(vulns)} unique CVE records.")
                        for v in vulns:
                            with st.expander(f"{v.cve_id} | Severity: {v.severity} | CVSS: {v.cvss_score} | Match: {v.match_confidence}"):
                                st.markdown(f"**Published:** {v.published_date}")
                                st.markdown(f"**Vector:** `{v.vector_string}`")
                                st.write(v.description)
                                st.markdown(f"**Remediation:** {v.remediation}")
                    else:
                        st.info("No matching records found in NVD.")
            else:
                st.warning("Please enter a search keyword.")

    elif module == "Threat Intel & IOC Triage":
        st.markdown("# // THREAT INTEL & IOC TRIAGE")
        st.markdown("<p style='color: #a0aec0;'>Analyze IP addresses, domains, or URLs against VirusTotal and AbuseIPDB feeds with granular parsing.</p>", unsafe_allow_html=True)

        indicator = st.text_input("Enter Indicator (IP Address, Domain, or URL)", placeholder="e.g., 8.8.8.8 or example.com")

        if st.button("Run Threat Triage Analysis", use_container_width=True):
            if indicator:
                with st.spinner(f"Querying threat intelligence feeds for `{indicator}`..."):
                    ti = ThreatIntelService(vt_key, abuse_key, cache=shared_cache)
                    report = ti.triage_indicator(indicator)
                    db.log_activity("Threat Intel Triage", indicator, "Completed")
                    st.success("Triage Analysis Complete.")

                    st.markdown("---")
                    col_vt, col_abuse = st.columns(2)

                    with col_vt:
                        st.subheader("VirusTotal Security Telemetry")
                        vt_sum = report['vt_summary']
                        if 'error' in vt_sum:
                            st.error(vt_sum['error'])
                        else:
                            m_count = vt_sum['malicious']
                            s_count = vt_sum['suspicious']
                            h_count = vt_sum['harmless']

                            st.metric("Malicious Detections", m_count, delta="Threat Flag" if m_count > 0 else "Clean", delta_color="inverse" if m_count > 0 else "normal")
                            st.metric("Suspicious Flags", s_count)
                            st.metric("Harmless Engines", h_count)
                            st.metric("Community Reputation Score", vt_sum['reputation'])
                            st.write(f"**Owner / Registrar / ASN:** `{vt_sum['registrar']}`")

                            with st.expander("View Full VirusTotal Raw JSON"):
                                st.json(report['vt_raw'])

                    with col_abuse:
                        st.subheader("AbuseIPDB Reputation Telemetry")
                        abuse_sum = report['abuse_summary']
                        if 'error' in abuse_sum:
                            st.error(abuse_sum['error'])
                        elif 'info' in abuse_sum:
                            st.info(abuse_sum['info'])
                        else:
                            score = abuse_sum['score']
                            reports = abuse_sum['reports']

                            st.metric("Abuse Confidence Score", f"{score}%", delta="High Risk" if score > 50 else "Low Risk", delta_color="inverse" if score > 50 else "normal")
                            st.metric("Total Abuse Reports", reports)
                            st.write(f"**Country Location:** `{abuse_sum['country']}`")
                            st.write(f"**ISP / Network:** `{abuse_sum['isp']}`")
                            st.write(f"**Last Reported:** `{abuse_sum['lastReported']}`")

                            with st.expander("View Full AbuseIPDB Raw JSON"):
                                st.json(report['abuse_raw'])
            else:
                st.warning("Please provide a valid indicator.")

    elif module == "Offensive Encoder & Hasher":
        st.markdown("# // PAYLOAD ENCODER, DECODER & HASHER")
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
        st.markdown("# // SQLITE AUDIT LOG HISTORY")
        history = db.get_history()
        if history:
            st.dataframe(pd.DataFrame(history), use_container_width=True)
        else:
            st.info("No recorded activity logs found.")

    elif module == "Platform Configuration":
        st.markdown("# // SYSTEM TELEMETRY & API CONFIGURATION")
        st.write(f"**NVD API Key Vault:** {'Configured' if nvd_key else 'Missing'}")
        st.write(f"**VirusTotal API Vault:** {'Configured' if vt_key else 'Missing'}")
        st.write(f"**AbuseIPDB API Vault:** {'Configured' if abuse_key else 'Missing'}")
        st.write(f"**Groq AI Engine Vault:** {'Configured (openai/gpt-oss-120b)' if groq_key else 'Missing'}")
        st.write("**SQLite Database:** Initialized & Encrypted")

if __name__ == "__main__":
    main()
