#ifndef WIFI_TEST_H
#define WIFI_TEST_H

#include <Arduino.h>

/**
 * Запускает инструмент пентеста WiFi для перехвата пакетов
 *
 * Собирает данные с WiFi сетей, включая пакеты аутентификации и handshake,
 * а затем передает их на ПК для дальнейшей обработки
 */
void wifi_test_run();

/**
 * Отправляет собранные данные на ПК через последовательный порт
 *
 * @param data_type Тип данных (PMKID, Handshake, и т.д.)
 * @param data_buffer Буфер с данными
 * @param data_length Длина данных
 * @return true если данные успешно отправлены, false в противном случае
 */
bool send_data_to_pc(const char *data_type, const uint8_t *data_buffer, size_t data_length);

/**
 * Отправляет информацию о сети на ПК
 *
 * @param ssid Имя сети
 * @param bssid MAC-адрес точки доступа
 * @param channel Канал сети
 * @param encryption_type Тип шифрования
 * @return true если информация успешно отправлена, false в противном случае
 */
bool send_network_info_to_pc(const String &ssid, const uint8_t *bssid, uint8_t channel, int encryption_type);

#endif // WIFI_TEST_H
