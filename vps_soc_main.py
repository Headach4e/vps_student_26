import os
import sys

# Добавляем текущую директорию в пути импорта Python
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Импортируем симулятор генерации логов
# try:
#     from vps_log_generator import generate_mock_ssh_logs, generate_mock_nginx_logs
# except ImportError:
#     print("[!] Не найден файл vps_log_generator.py. Убедитесь, что он лежит в той же папке!")
#     sys.exit(1)

# Импортируем студенческий модуль аналитики
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

    try:
        with open(ssh_log_path, "r") as f:
            ssh_logs = f.readlines()
    except FileNotFoundError:
        print(f"    [!] Файл {ssh_log_path} не найден! Проверьте путь.")
        return

    # ==========================================
    # ГРУППИРОВКА АТАК ПО IP
    # ==========================================
    # Что делает эта строка:
    # 1. Вызывает функцию group_by_ip из нашего модуля analyzer
    # 2. Передаёт ей список всех строк SSH-логов (ssh_logs)
    # 3. Функция анализирует каждую строку, находит IP и считает атаки
    # 4. Возвращает словарь вида: {"IP": количество_атак}
    #
    # Пример результата:
    # ip_attempts = {"192.168.1.1": 10, "10.0.0.1": 3, "8.8.8.8": 7}
    #
    # Узнаем сколько раз каждый IP пытался войти
    ip_attempts = analyzer.group_by_ip(ssh_logs)

    print(f"    - Всего уникальных IP, совершивших неудачный вход: {len(ip_attempts)}")
    for ip, count in sorted(ip_attempts.items(), key=lambda x: x[1], reverse=True)[:3]:
        print(f"      * IP: {ip} - {count} неудачных попыток")

    # ==========================================
    # ДЕТЕКТОР БРУТФОРС-АТАК
    # ==========================================
    # Что делает эта строка:
    # 1. Вызывает функцию detect_brute_force из нашего модуля analyzer
    # 2. Передаёт ей словарь с атаками (ip_attempts) и порог (5)
    # 3. Функция проверяет, у каких IP количество атак >= 5
    # 4. Возвращает список IP, которые превысили порог
    #
    # Пример результата:
    # bf_alerts = ["192.168.1.1", "8.8.8.8"]  # эти IP нужно заблокировать
    #
    # Почему порог 5?
    # Если с одного IP 5 и более неудачных попыток - это явный признак
    # автоматического подбора пароля (брутфорс-атаки)
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

    try:
        with open(nginx_log_path, "r") as f:
            nginx_logs = f.readlines()
    except FileNotFoundError:
        print(f"    [!] Файл {nginx_log_path} не найден. Пропускаем веб-анализ.")
        nginx_logs = []

    web_alerts_count = 0
    print("    - Подозрительные веб-запросы:")
    for line in nginx_logs:  # ← ИСПРАВЛЕНО! была одна строка, убрал дублирование
        # ==========================================
        # ПОИСК ВЕБ-АТАК
        # ==========================================
        # Что делает эта строка:
        # 1. Вызывает функцию detect_suspicious_paths из нашего модуля analyzer
        # 2. Передаёт ей текущую строку лога (line)
        # 3. Функция проверяет, есть ли в строке опасные сигнатуры:
        #    - /etc/passwd (попытка прочитать пароли)
        #    - .env (попытка прочитать секреты)
        #    - wp-admin (попытка взломать WordPress)
        #    - select+union / union+select (SQL-инъекция)
        #    - shell.php (попытка загрузить вредоносный скрипт)
        # 4. Возвращает True (опасно) или False (безопасно)
        #
        # Пример:
        # line = 'GET /etc/passwd HTTP/1.1'
        # is_suspicious = True  ← это атака!
        #
        # line = 'GET /index.html HTTP/1.1'
        # is_suspicious = False  ← это обычный запрос
        is_suspicious = analyzer.detect_suspicious_paths(line)

        if is_suspicious:
            web_alerts_count += 1
            parts = line.split('"')
            request = parts[1] if len(parts) > 1 else line.strip()
            ip = line.split()[0]
            print(f"      [ALERT] {ip} запросил опасный путь: '{request}'")

    print(f"    - Всего зафиксировано подозрительных веб-запросов: {web_alerts_count}")
    print("-" * 60)

    # Шаг 4: Расчет риска для VPS
    print("[4] Оценка уровня угрозы VPS (Risk Scoring):")
    # ==========================================
    #  РАСЧЕТ УРОВНЯ РИСКА
    # ==========================================
    # Что делает эта строка:
    # 1. Вызывает функцию calculate_risk_score из нашего модуля analyzer
    # 2. Передаёт ей:
    #    - len(bf_alerts) - количество обнаруженных брутфорс-атак
    #    - web_alerts_count - количество обнаруженных веб-атак
    # 3. Функция считает баллы:
    #    - Каждая брутфорс-атака = 3 балла (очень опасно)
    #    - Каждая веб-атака = 1 балл (менее опасно)
    # 4. Возвращает уровень риска:
    #    - "LOW"   (0 баллов - нет атак)
    #    - "MEDIUM" (1-4 балла - есть угрозы)
    #    - "HIGH"  (5+ баллов - критическая ситуация!)
    #
    # Примеры:
    #   bf_alerts = [], web_alerts_count = 0 → score = 0 → "LOW"
    #   bf_alerts = ["1.1.1.1"], web_alerts_count = 1 → score = 4 → "MEDIUM"
    #   bf_alerts = ["1.1.1.1", "2.2.2.2"], web_alerts_count = 0 → score = 6 → "HIGH"
    risk = analyzer.calculate_risk_score(len(bf_alerts), web_alerts_count)

    print(f"    - УРОВЕНЬ РИСКА ДЛЯ VPS: **{risk}**")
    print("-" * 60)

    # Шаг 5: Проверка целостности файлов на VPS
    print("[5] Контроль целостности файлов на VPS:")
    dummy_config = "/tmp/vps_secure_config.conf"

    with open(dummy_config, "w") as f:
        f.write("PermitRootLogin no\nPasswordAuthentication no\n")

    # ==========================================
    # ХЕШ ИСХОДНОГО ФАЙЛА (ПЕРВАЯ)
    # ==========================================
    # Что делает эта строка:
    # 1. Вызывает функцию get_file_hash из нашего модуля analyzer
    # 2. Передаёт ей путь к файлу (dummy_config)
    # 3. Функция открывает файл, читает его и вычисляет SHA-256 хеш
    # 4. Возвращает хеш в виде 64-символьной строки
    #
    # Что такое SHA-256 хеш?
    # Это как "отпечаток пальца" файла.
    # Если изменить хотя бы 1 байт в файле - хеш полностью изменится.
    # Это позволяет проверить, не изменил ли кто-то файл.
    #
    # Пример:
    #   hash_original = "a8f5f167f44f4964e6c998d..." (64 символа)
    # Если кто-то изменит файл, новый хеш будет другим!
    hash_original = analyzer.get_file_hash(dummy_config)
    print(f"    - Хеш-сумма файла {dummy_config} (SHA-256): {hash_original}")

    # Симулируем несанкционированное изменение (взлом)
    with open(dummy_config, "a") as f:
        f.write("PermitRootLogin yes # ХАКЕР ИЗМЕНИЛ НАСТРОЙКУ!\n")

    # ==========================================
    # ХЕШ ИЗМЕНЕННОГО ФАЙЛА (ВТОРАЯ)
    # ==========================================
    # Что делает эта строка:
    # 1. Вызывает функцию get_file_hash из нашего модуля analyzer
    # 2. Передаёт ей путь к файлу (dummy_config)
    # 3. Функция вычисляет хеш файла (который мы только что изменили)
    # 4. Возвращает хеш измененного файла
    #
    # Теперь мы можем сравнить два хеша:
    # - hash_original (до изменения)
    # - hash_modified (после изменения)
    # Если они разные - файл был изменён!
    #
    # Это как сравнить отпечатки пальцев: если они разные -
    # значит, файл кто-то трогал!
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
        # ==========================================
        # ПРОВЕРКА ОТКРЫТЫХ ПОРТОВ
        # ==========================================
        # Что делает эта строка:
        # 1. Вызывает функцию is_port_open из нашего модуля analyzer
        # 2. Передаёт ей:
        #    - "127.0.0.1" (localhost - наш собственный компьютер)
        #    - port (текущий порт из списка: 22, 80, 443 или 8080)
        #    - timeout=0.5 (ждём ответ полсекунды, потом сдаёмся)
        # 3. Функция пытается подключиться к порту
        # 4. Возвращает True (порт открыт) или False (порт закрыт)
        #
        # Что такое порт?
        # Это как "дверь" в компьютер. У каждой программы своя дверь:
        # - 22  = SSH (для удаленного управления)
        # - 80  = HTTP (обычные сайты)
        # - 443 = HTTPS (безопасные сайты)
        # - 8080 = альтернативный HTTP (часто для тестов)
        #
        # Если порт открыт - значит, сервер слушает запросы на этом порту
        # Если порт закрыт - значит, никто не отвечает
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