#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Bruce WiFi Tool - PC Client

Этот скрипт принимает данные от устройства Bruce через последовательный порт,
обрабатывает перехваченные WiFi-пакеты и передает их для взлома инструментам
вроде Hashcat.

Требования:
- Python 3.6+
- pyserial
- hashcat (опционально, для автоматического взлома)
"""

import argparse
import binascii  # Встроенный модуль Python
import os
import subprocess
import sys
import time
from datetime import datetime

import serial

# Константы
PACKET_HEADER = "BRUCE_WIFI_DATA"
DATA_TYPE_NETWORK_INFO = "NET_INFO"
DATA_TYPE_PMKID = "PMKID"
DATA_TYPE_HANDSHAKE = "HANDSHAKE"
DATA_TYPE_RAW_PACKET = "RAW_PKT"

# Глобальные переменные
captured_networks = {}
captured_pmkid = {}
captured_handshakes = {}
captured_packets = []

def init_serial_port(port, baudrate=115200, timeout=1):
    """Инициализация последовательного порта"""
    try:
        ser = serial.Serial(port, baudrate, timeout=timeout)
        print(f"[+] Успешно подключен к порту {port} на скорости {baudrate} бод")
        return ser
    except Exception as e:
        print(f"[!] Ошибка при открытии порта {port}: {e}")
        sys.exit(1)

def parse_network_info(data_hex):
    """Разбор информации о сети из полученных данных"""
    data = bytearray.fromhex(data_hex)
    if len(data) < 10:
        print("[!] Некорректные данные о сети")
        return None

    channel = data[0]
    encryption_type = data[1]
    bssid = ':'.join(f'{b:02x}' for b in data[2:8])
    ssid_len = data[8]
    ssid = data[9:9+ssid_len].decode('utf-8', errors='replace')

    # Определение типа шифрования
    encryption_name = "Unknown"
    if encryption_type == 0:
        encryption_name = "Open"
    elif encryption_type == 1:
        encryption_name = "WEP"
    elif encryption_type == 2:
        encryption_name = "WPA/PSK"
    elif encryption_type == 3:
        encryption_name = "WPA2/PSK"
    elif encryption_type == 4:
        encryption_name = "WPA/WPA2/PSK"
    elif encryption_type == 5:
        encryption_name = "WPA2/Enterprise"

    network_info = {
        'ssid': ssid,
        'bssid': bssid,
        'channel': channel,
        'encryption_type': encryption_type,
        'encryption_name': encryption_name
    }

    return network_info

def parse_pmkid(data_hex, associated_network=None):
    """Разбор PMKID из полученных данных"""
    if len(data_hex) < 32:
        print("[!] Некорректные данные PMKID")
        return None

    pmkid = data_hex

    if associated_network:
        # Формат для Hashcat: PMKID*SSID*AP_MAC*STA_MAC
        hashcat_format = f"{pmkid}*{associated_network['ssid']}*{associated_network['bssid'].replace(':', '')}*"
        return {
            'pmkid': pmkid,
            'hashcat_format': hashcat_format,
            'network': associated_network
        }
    else:
        return {'pmkid': pmkid}

def save_to_file(data, filename, mode='a'):
    """Сохранение данных в файл"""
    try:
        with open(filename, mode) as f:
            f.write(data + '\n')
        return True
    except Exception as e:
        print(f"[!] Ошибка при сохранении в файл {filename}: {e}")
        return False

def run_hashcat(hash_file, wordlist, hash_mode):
    """Запуск Hashcat для взлома пароля"""
    cmd = [
        "hashcat",
        "-m", str(hash_mode),  # 22000 для PMKID, 16800 для WPA/WPA2
        "-a", "0",             # Режим атаки: словарь
        hash_file,
        wordlist
    ]

    print(f"[*] Запуск Hashcat: {' '.join(cmd)}")

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )

        print("[*] Hashcat запущен в фоновом режиме. Проверьте файл found_passwords.txt после завершения.")
        return process
    except Exception as e:
        print(f"[!] Ошибка при запуске Hashcat: {e}")
        return None

def process_data(ser, output_dir, wordlist):
    """Обработка данных от Bruce"""
    current_data = None
    data_type = None
    data_length = 0
    reading_data = False
    data_hex = ""

    try:
        while True:
            line = ser.readline().decode('utf-8', errors='replace').strip()

            if not line:
                continue

            # Специальные команды от Bruce
            if line == "BRUCE_WIFI_TOOL_START":
                print("[+] Bruce WiFi Tool запущен")
                continue

            if line == "BRUCE_WIFI_TOOL_END":
                print("[+] Bruce WiFi Tool завершен")
                continue

            if line == "SCAN_RESULTS":
                networks_count = int(ser.readline().decode('utf-8', errors='replace').strip())
                print(f"[+] Найдено {networks_count} WiFi сетей")
                continue

            if line == "START_DEAUTH":
                ssid = ser.readline().decode('utf-8', errors='replace').strip().split(':', 1)[1]
                bssid = ser.readline().decode('utf-8', errors='replace').strip().split(':', 1)[1]
                channel = ser.readline().decode('utf-8', errors='replace').strip().split(':', 1)[1]
                print(f"[+] Начало деаутентификации сети {ssid} (BSSID: {bssid}, канал: {channel})")
                continue

            if line == "END_DEAUTH":
                print("[+] Деаутентификация завершена")
                continue

            if line == "START_PMKID_CAPTURE":
                ssid = ser.readline().decode('utf-8', errors='replace').strip().split(':', 1)[1]
                bssid = ser.readline().decode('utf-8', errors='replace').strip().split(':', 1)[1]
                channel = ser.readline().decode('utf-8', errors='replace').strip().split(':', 1)[1]
                print(f"[+] Начало захвата PMKID/Handshake для сети {ssid} (BSSID: {bssid}, канал: {channel})")
                continue

            if line == "END_PMKID_CAPTURE":
                print("[+] Захват PMKID/Handshake завершен")
                continue

            # Обработка пакетов данных
            if line == PACKET_HEADER:
                reading_data = True
                version = int(ser.readline().decode('utf-8', errors='replace').strip())
                data_type = ser.readline().decode('utf-8', errors='replace').strip()
                data_length = int(ser.readline().decode('utf-8', errors='replace').strip())
                print(f"[*] Получаем данные типа {data_type}, размер: {data_length} байт")
                continue

            if reading_data and line != f"END_{PACKET_HEADER}":
                data_hex = line
                continue

            if reading_data and line == f"END_{PACKET_HEADER}":
                reading_data = False

                # Обработка информации о сети
                if data_type == DATA_TYPE_NETWORK_INFO:
                    network_info = parse_network_info(data_hex)
                    if network_info:
                        network_id = network_info['bssid']
                        captured_networks[network_id] = network_info
                        print(f"[+] Добавлена информация о сети: {network_info['ssid']} ({network_info['bssid']})")

                # Обработка PMKID
                elif data_type == DATA_TYPE_PMKID:
                    # Ищем последнюю активную сеть
                    latest_network = None
                    for net_id in captured_networks:
                        if not latest_network or captured_networks[net_id].get('last_seen', 0) > latest_network.get('last_seen', 0):
                            latest_network = captured_networks[net_id]

                    pmkid_info = parse_pmkid(data_hex, latest_network)
                    if pmkid_info:
                        # Сохраняем PMKID в формате для Hashcat
                        if 'hashcat_format' in pmkid_info:
                            hash_file = os.path.join(output_dir, "pmkid_hashes.txt")
                            save_to_file(pmkid_info['hashcat_format'], hash_file)
                            print(f"[+] PMKID сохранен в {hash_file}")

                            # Запускаем Hashcat
                            run_hashcat(hash_file, wordlist, 22000)

                        # Сохраняем сырой PMKID
                        captured_pmkid[pmkid_info.get('network', {}).get('bssid', 'unknown')] = pmkid_info

                # Обработка полного handshake
                elif data_type == DATA_TYPE_HANDSHAKE:
                    # Здесь будет обработка handshake (более сложная логика)
                    print("[+] Получен полный WPA handshake")

                    # Для примера просто сохраняем сырые данные
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    handshake_file = os.path.join(output_dir, f"handshake_{timestamp}.bin")
                    with open(handshake_file, 'wb') as f:
                        f.write(binascii.unhexlify(data_hex))
                    print(f"[+] Handshake сохранен в {handshake_file}")

                # Обработка сырого пакета
                elif data_type == DATA_TYPE_RAW_PACKET:
                    # Сохраняем пакет для последующего анализа
                    captured_packets.append(data_hex)
                    # Можно также сохранять в формате pcap для анализа в Wireshark

                data_type = None
                data_length = 0
                data_hex = ""

    except KeyboardInterrupt:
        print("\n[*] Программа остановлена пользователем")
    except Exception as e:
        print(f"[!] Ошибка при обработке данных: {e}")

def main():
    # Парсинг аргументов командной строки
    parser = argparse.ArgumentParser(description='Bruce WiFi Tool - PC Client')
    parser.add_argument('-p', '--port', required=True, help='Последовательный порт (например, COM3 или /dev/ttyUSB0)')
    parser.add_argument('-b', '--baudrate', type=int, default=115200, help='Скорость порта (бод)')
    parser.add_argument('-o', '--output', default='./wifi_data', help='Каталог для сохранения данных')
    parser.add_argument('-w', '--wordlist', default='./wordlist.txt', help='Путь к словарю для Hashcat')

    args = parser.parse_args()

    # Создаем выходной каталог, если он не существует
    if not os.path.exists(args.output):
        os.makedirs(args.output)

    # Инициализация последовательного порта
    ser = init_serial_port(args.port, args.baudrate)

    print("[*] Bruce WiFi Tool PC Client запущен")
    print("[*] Ожидание данных от устройства Bruce...")

    # Обработка данных
    process_data(ser, args.output, args.wordlist)

    # Закрываем последовательный порт
    if ser and ser.is_open:
        ser.close()

if __name__ == "__main__":
    main()
