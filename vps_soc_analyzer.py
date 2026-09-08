import re
import socket
import hashlib


def extract_ip(log_line: str) -> str | None:
    """
    Извлекает IPv4-адрес из строки неудачной SSH-аутентификации.
    Для успешных входов и некорректных строк возвращает None.
    """
    if "Failed password" in log_line or "Invalid user" in log_line:
        match = re.search(r'from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', log_line)
        if match:
            return match.group(1)
        return None
    return None

def group_by_ip(log_lines: list[str]) -> dict[str, int]:
    """
    Подсчитывает количество неудачных SSH-входов для каждого IP-адреса.
    """
    attacks = {}
    for line in log_lines:
        ip = extract_ip(line)
        if ip:
            attacks[ip] = attacks.get(ip, 0) + 1
    return attacks

def detect_brute_force(ip_counts: dict[str, int], threshold: int = 5) -> list[str]:
    """
    Возвращает IP-адреса, у которых количество неудачных входов
    больше или равно заданному порогу.
    """
    DANGEROUS = []
    for ip, count in ip_counts.items():
        if count >= threshold:
            DANGEROUS.append(ip)
    return DANGEROUS

def detect_suspicious_paths(log_line: str) -> bool:
    """
    Ищет известные сигнатуры подозрительных веб-запросов.
    """
    signatures = (
        "/etc/passwd",
        ".env",
        "wp-admin",
        "select+union",
        "union+select",
        "shell.php",
    )

    lowered = log_line.lower()
    return any(signature in lowered for signature in signatures)


def calculate_risk_score(brute_force_alerts: int, web_alerts: int) -> str:
    """
    Рассчитывает уровень риска:
    brute-force алерт = 3 балла, web-алерт = 1 балл.
    """
    score = brute_force_alerts * 3 + web_alerts

    if score == 0:
        return "LOW"
    if score < 5:
        return "MEDIUM"
    return "HIGH"


def is_port_open(ip: str, port: int, timeout: float = 1.0) -> bool:
    """
    Проверяет доступность TCP-порта.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((ip, port)) == 0
    except (OSError, ValueError, socket.error):
        return False


def get_file_hash(filepath: str) -> str:
    """
    Возвращает SHA-256 файла либо FILE_NOT_FOUND, если файла нет.
    Файл читается блоками, чтобы не загружать его целиком в память.
    """
    sha256 = hashlib.sha256()

    try:
        with open(filepath, "rb") as file:
            while True:
                chunk = file.read(8192)
                if not chunk:
                    break
                sha256.update(chunk)
    except FileNotFoundError:
        return "FILE_NOT_FOUND"

    return sha256.hexdigest()