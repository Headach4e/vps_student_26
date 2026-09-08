import os
import sys

# Чтобы можно было импортировать соседний модуль (vps_soc_analyzer),
# добавляем папку со скриптом в пути поиска модулей Python
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Импортируем симулятор генерации логов
# try:
#     from vps_log_generator import generate_mock_ssh_logs, generate_mock_nginx_logs
# except ImportError:
#     print("[!] Не найден файл vps_log_generator.py. Убедитесь, что он лежит в той же папке!")
#     sys.exit(1)

# Подключаем модуль с аналитикой (его пишет студент).
# Если файла нет — сразу падаем с понятным сообщением, а не с traceback
try:
    import vps_soc_analyzer as analyzer
except ImportError:
    print("[!] Не найден файл vps_soc_analyzer.py. Переименуйте шаблон или создайте его!")
    sys.exit(1)


def run_pipeline():
    print("=" * 60)
    print("ЗАПУСК КОНВЕЙЕРА (PIPELINE) МИНИ-SOC НА VPS (СТУДЕНЧЕСКИЙ ШАБЛОН)")
    print("=" * 60)

    # Шаг 1: Симуляция/Генерация данных на сервере (Уже реализовано)
    print("[1] Симуляция: Создаем искусственные логи на сервере...")
    # mock_ssh_lines = generate_mock_ssh_logs(num_lines=100)
    # mock_nginx_lines = generate_mock_nginx_logs(num_lines=50)

    # ssh_log_path = "mock_auth.log"
    # nginx_log_path = "mock_nginx_access.log"

    # with open(ssh_log_path, "w") as f:
    #     f.writelines([line + "\n" for line in mock_ssh_lines])
    # with open(nginx_log_path, "w") as f:
    #     f.writelines([line + "\n" for line in mock_nginx_lines])

    # print(f"    - Сгенерировано строк SSH: {len(mock_ssh_lines)} (сохранено в {ssh_log_path})")
    # print(f"    - Сгенерировано строк Nginx: {len(mock_nginx_lines)} (сохранено в {nginx_log_path})")
    # print("-" * 60)

    # Шаг 2: Анализ логов SSH (Брутфорс)
    print("[2] Анализ SSH логов:")
    # with open(ssh_log_path, "r") as f:
    #     ssh_logs = f.readlines()

    # ПУТЬ К РЕАЛЬНЫМ ЛОГАМ НА СЕРВЕРЕ
    ssh_log_path = "/home/student/logs/auth.log"

    # Читаем реальный лог-файл; если его нет по указанному пути — прерываем пайплайн.
    try:
        with open(ssh_log_path, "r") as f:
            ssh_logs = f.readlines()
    except FileNotFoundError:
        print(f"    [!] Файл {ssh_log_path} не найден! Проверьте путь.")
        return

    # Группируем все строки SSH-лога по IP: получаем словарь
    # {"IP": количество неудачных попыток входа}
    ip_attempts = analyzer.group_by_ip(ssh_logs)

    print(f"    - Всего уникальных IP, совершивших неудачный вход: {len(ip_attempts)}")
    for ip, count in sorted(ip_attempts.items(), key=lambda x: x[1], reverse=True)[:3]:
        print(f"      * IP: {ip} - {count} неудачных попыток")

    # Из всех IP отбираем тех, кто превысил порог в 5 попыток —
    # это и считаем признаком брутфорс-атаки.
    bf_alerts = analyzer.detect_brute_force(ip_attempts, threshold=5)

    print(f"    - ОБНАРУЖЕНО БРУТФОРС-АТАК (>= 5 попыток): {len(bf_alerts)}")
    for ip in bf_alerts:
        print(f"      [ALERT] IP {ip} превысил порог и заблокирован в SOC!")
    print("-" * 60)

    # Шаг 3: Анализ веб-логов (Nginx)
    print("[3] Анализ веб-логов (Nginx):")
    # with open(nginx_log_path, "r") as f:
    #     nginx_logs = f.readlines()

    # ПУТЬ К РЕАЛЬНЫМ ВЕБ-ЛОГАМ (если есть)
    nginx_log_path = "/home/student/logs/nginx_access.log"

    # Веб-логов может не быть — тогда просто пропускаем этот блок анализа,
    # а не прерываем весь пайплайн.
    try:
        with open(nginx_log_path, "r") as f:
            nginx_logs = f.readlines()
    except FileNotFoundError:
        print(f"    [!] Файл {nginx_log_path} не найден. Пропускаем веб-анализ.")
        nginx_logs = []

    web_alerts_count = 0
    print("    - Подозрительные веб-запросы:")
    for line in nginx_logs:  # ← ИСПРАВЛЕНО! была одна строка, убрал дублирование
        # Проверяем строку лога на сигнатуры типовых веб-атак
        # (чтение системных файлов, попытки взлома WordPress, SQL-инъекции и т.д.)
        is_suspicious = analyzer.detect_suspicious_paths(line)

        if is_suspicious:
            web_alerts_count += 1
            # Достаём из строки лога сам запрос (между кавычками) и IP-адрес (первое поле)
            parts = line.split('"')
            request = parts[1] if len(parts) > 1 else line.strip()
            ip = line.split()[0]
            print(f"      [ALERT] {ip} запросил опасный путь: '{request}'")

    print(f"    - Всего зафиксировано подозрительных веб-запросов: {web_alerts_count}")
    print("-" * 60)

    # Шаг 4: Расчет риска для VPS
    print("[4] Оценка уровня угрозы VPS (Risk Scoring):")
    # Сводим число брутфорс- и веб-алертов в единый уровень риска: LOW/MEDIUM/HIGH
    risk = analyzer.calculate_risk_score(len(bf_alerts), web_alerts_count)

    print(f"    - УРОВЕНЬ РИСКА ДЛЯ VPS: **{risk}**")
    print("-" * 60)

    # Шаг 5: Проверка целостности файлов на VPS
    print("[5] Контроль целостности файлов на VPS:")
    dummy_config = "/tmp/vps_secure_config.conf"

    with open(dummy_config, "w") as f:
        f.write("PermitRootLogin no\nPasswordAuthentication no\n")

    # Считаем SHA-256 хеш файла ДО изменения — это "эталонный отпечаток"
    hash_original = analyzer.get_file_hash(dummy_config)
    print(f"    - Хеш-сумма файла {dummy_config} (SHA-256): {hash_original}")

    # Симулируем несанкционированное изменение (взлом)
    with open(dummy_config, "a") as f:
        f.write("PermitRootLogin yes # ХАКЕР ИЗМЕНИЛ НАСТРОЙКУ!\n")

    # Считаем хеш ПОСЛЕ изменения и сравниваем с эталоном —
    # так обнаруживается сам факт модификации файла
    hash_modified = analyzer.get_file_hash(dummy_config)
    print(f"    - Хеш-сумма после изменения: {hash_modified}")

    if hash_original != hash_modified:
        print("    - [!] ВНИМАНИЕ: Целостность конфигурационного файла НАРУШЕНА!")
    else:
        print("    - [OK] Файл конфигурации не изменен.")
    print("-" * 60)

    # Шаг 6: Проверка доступности портов на VPS (Тестируем локально)
    print("[6] Сетевая разведка (Тестовый сканер портов):")
    ports_to_scan = [22, 80, 443, 8080]
    print(f"    - Сканируем порты на localhost (127.0.0.1): {ports_to_scan}")
    for port in ports_to_scan:  # ← ИСПРАВЛЕНО! была одна строка, убрал дублирование
        # Пробуем подключиться к каждому порту на localhost с коротким таймаутом:
        # открытый порт означает, что там что-то слушает входящие соединения
        is_open = analyzer.is_port_open("127.0.0.1", port, timeout=0.5)

        status = "ОТКРЫТ" if is_open else "ЗАКРЫТ"
        print(f"      * Порт {port}: {status}")
    print("-" * 60)

    # Очистка временных файлов (Уже реализовано)
    for file in [ssh_log_path, nginx_log_path, dummy_config]:
        if os.path.exists(file):
            os.remove(file)

    print("ЗАВЕРШЕНИЕ РАБОТЫ.")
    print("=" * 60)


if __name__ == "__main__":
    run_pipeline()