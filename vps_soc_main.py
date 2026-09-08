import os
import sys

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from vps_log_generator import generate_mock_ssh_logs, generate_mock_nginx_logs
except ImportError:
    print("[!] Не найден файл vps_log_generator.py. Убедитесь, что он лежит в той же папке!")
    sys.exit(1)

try:
    import vps_soc_analyzer as analyzer
except ImportError:
    print("[!] Не найден файл vps_soc_analyzer.py.")
    sys.exit(1)


def run_pipeline() -> None:
    print("=" * 60)
    print("ЗАПУСК КОНВЕЙЕРА (PIPELINE) МИНИ-SOC НА VPS")
    print("=" * 60)

    # Шаг 1: генерация тестовых логов
    print("[1] Симуляция: создаем искусственные логи на сервере...")
    mock_ssh_lines = generate_mock_ssh_logs(num_lines=100)
    mock_nginx_lines = generate_mock_nginx_logs(num_lines=50)

    ssh_log_path = "mock_auth.log"
    nginx_log_path = "mock_nginx_access.log"

    with open(ssh_log_path, "w", encoding="utf-8") as file:
        file.writelines([line + "\n" for line in mock_ssh_lines])

    with open(nginx_log_path, "w", encoding="utf-8") as file:
        file.writelines([line + "\n" for line in mock_nginx_lines])

    print(f" - Сгенерировано строк SSH: {len(mock_ssh_lines)}")
    print(f" - Сгенерировано строк Nginx: {len(mock_nginx_lines)}")
    print("-" * 60)

    # Шаг 2: SSH
    print("[2] Анализ SSH логов:")
    with open(ssh_log_path, "r", encoding="utf-8") as file:
        ssh_logs = file.readlines()

    ip_attempts = analyzer.group_by_ip(ssh_logs)

    print(
        " - Всего уникальных IP, совершивших неудачный вход: "
        f"{len(ip_attempts)}"
    )

    for ip, count in sorted(
        ip_attempts.items(),
        key=lambda item: item[1],
        reverse=True,
    )[:3]:
        print(f" * IP: {ip} - {count} неудачных попыток")

    bf_alerts = analyzer.detect_brute_force(ip_attempts, threshold=5)

    print(
        " - ОБНАРУЖЕНО БРУТФОРС-АТАК (>= 5 попыток): "
        f"{len(bf_alerts)}"
    )

    for ip in bf_alerts:
        print(f" [ALERT] IP {ip} превысил порог!")

    print("-" * 60)

    # Шаг 3: Nginx
    print("[3] Анализ веб-логов (Nginx):")
    with open(nginx_log_path, "r", encoding="utf-8") as file:
        nginx_logs = file.readlines()

    web_alerts_count = 0
    print(" - Подозрительные веб-запросы:")

    for line in nginx_logs:
        is_suspicious = analyzer.detect_suspicious_paths(line)

        if is_suspicious:
            web_alerts_count += 1
            parts = line.split('"')
            request = parts[1] if len(parts) > 1 else line.strip()
            ip = line.split()[0] if line.split() else "UNKNOWN"
            print(f" [ALERT] {ip} запросил опасный путь: '{request}'")

    print(
        " - Всего зафиксировано подозрительных веб-запросов: "
        f"{web_alerts_count}"
    )
    print("-" * 60)

    # Шаг 4: Risk Scoring
    print("[4] Оценка уровня угрозы VPS (Risk Scoring):")
    risk = analyzer.calculate_risk_score(len(bf_alerts), web_alerts_count)
    print(f" - УРОВЕНЬ РИСКА ДЛЯ VPS: **{risk}**")
    print("-" * 60)

    # Шаг 5: контроль целостности
    print("[5] Контроль целостности файлов на VPS:")
    dummy_config = "vps_secure_config.conf"

    with open(dummy_config, "w", encoding="utf-8") as file:
        file.write("PermitRootLogin no\nPasswordAuthentication no\n")

    hash_original = analyzer.get_file_hash(dummy_config)
    print(f" - Исходный SHA-256: {hash_original}")

    with open(dummy_config, "a", encoding="utf-8") as file:
        file.write("PermitRootLogin yes # ХАКЕР ИЗМЕНИЛ НАСТРОЙКУ!\n")

    hash_modified = analyzer.get_file_hash(dummy_config)
    print(f" - SHA-256 после изменения: {hash_modified}")

    if hash_original != hash_modified:
        print(" - [!] ВНИМАНИЕ: целостность файла НАРУШЕНА!")
    else:
        print(" - [OK] Файл конфигурации не изменен.")

    print("-" * 60)

    # Шаг 6: сканирование портов
    print("[6] Сетевая разведка (тестовый сканер портов):")
    ports_to_scan = [22, 80, 443, 8080]
    print(f" - Сканируем localhost: {ports_to_scan}")

    for port in ports_to_scan:
        is_open = analyzer.is_port_open("127.0.0.1", port)
        status = "ОТКРЫТ" if is_open else "ЗАКРЫТ"
        print(f" * Порт {port}: {status}")

    print("-" * 60)

    # Очистка
    for filepath in (ssh_log_path, nginx_log_path, dummy_config):
        if os.path.exists(filepath):
            os.remove(filepath)

    print("КОНВЕЙЕР ЗАВЕРШИЛ РАБОТУ.")
    print("=" * 60)


if __name__ == "__main__":
    run_pipeline()
