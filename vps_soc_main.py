import os
import sys

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import vps_soc_analyzer as analyzer


def run_pipeline():
    print("=" * 60)
    print("АНАЛИЗ РЕАЛЬНЫХ ЛОГОВ VPS")
    print("=" * 60)

    # Путь к реальному SSH-логу
    ssh_log_path = os.path.expanduser("~/logs/auth.log")

    if not os.path.exists(ssh_log_path):
        print(f"[!] Файл не найден: {ssh_log_path}")
        return

    print(f"[1] Читаем SSH-лог: {ssh_log_path}")

    with open(ssh_log_path, "r", encoding="utf-8", errors="ignore") as file:
        ssh_logs = file.readlines()

    print(f" - Всего строк в логе: {len(ssh_logs)}")

    # Подсчет неудачных входов
    ip_attempts = analyzer.group_by_ip(ssh_logs)

    print(
        " - Уникальных IP с неудачными попытками входа: "
        f"{len(ip_attempts)}"
    )

    for ip, count in sorted(
        ip_attempts.items(),
        key=lambda item: item[1],
        reverse=True
    ):
        print(f" * {ip}: {count} неудачных попыток")

    # Поиск brute-force
    bf_alerts = analyzer.detect_brute_force(
        ip_attempts,
        threshold=5
    )

    print("-" * 60)
    print(f"ОБНАРУЖЕНО BRUTE-FORCE IP: {len(bf_alerts)}")

    for ip in bf_alerts:
        print(
            f"[ALERT] {ip} совершил "
            f"{ip_attempts[ip]} неудачных попыток входа"
        )

    # Оценка риска
    risk = analyzer.calculate_risk_score(
        len(bf_alerts),
        0
    )

    print("-" * 60)
    print(f"УРОВЕНЬ РИСКА: {risk}")
    print("=" * 60)


if __name__ == "__main__":
    run_pipeline()