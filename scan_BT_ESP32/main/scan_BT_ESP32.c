/*
   ECSE 4660: Internetworking of Things Spring 2021
   Final Project: Main Script for ESP32 Bluetooth Scanning
   Original Source: https://github.com/espressif/esp-idf/blob/master/examples/bluetooth/bluedroid/classic_bt/bt_discovery/main/bt_discovery.c
   Author: Rahul Jain
   This example code is in the Public Domain (or CC0 licensed, at your option.)
   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/

/****************************************************************************
*
* This file is from a Classic Bluetooth device and service discovery demo.
* File has been heavily modified for the project application
* 
****************************************************************************/

#include <stdint.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "esp_system.h"
#include "esp_log.h"
#include "esp_bt.h"
#include "esp_bt_main.h"
#include "esp_bt_device.h"
#include "esp_gap_bt_api.h"
// Following are for wifi
#include "wifi_setup.c"
#include <lwip/sockets.h>
#include "sdkconfig.h"
// AES Encryption
#include "mbedtls/aes.h"

#define GAP_TAG          "GAP"
#define SOCKET_TAG "socketClient"

#define SERVER_IP "192.168.86.217" // IP Reserved
#define SERVER_PORT 9999

char btSsid[10000];

typedef enum {
    APP_GAP_STATE_IDLE = 0,
    APP_GAP_STATE_DEVICE_DISCOVERING,
    APP_GAP_STATE_DEVICE_DISCOVER_COMPLETE,
    APP_GAP_STATE_SERVICE_DISCOVERING,
    APP_GAP_STATE_SERVICE_DISCOVER_COMPLETE,
} app_gap_state_t;

typedef struct {
    bool dev_found;
    uint8_t bdname_len;
    uint8_t eir_len;
    uint8_t rssi;
    uint32_t cod;
    uint8_t eir[ESP_BT_GAP_EIR_DATA_LEN];
    uint8_t bdname[ESP_BT_GAP_MAX_BDNAME_LEN + 1];
    esp_bd_addr_t bda;
    app_gap_state_t state;
} app_gap_cb_t;

static app_gap_cb_t m_dev_info;
int isStarted = 0;

static char *bda2str(esp_bd_addr_t bda, char *str, size_t size)
{
    if (bda == NULL || str == NULL || size < 18) {
        return NULL;
    }

    uint8_t *p = bda;
    sprintf(str, "%02x:%02x:%02x:%02x:%02x:%02x",
            p[0], p[1], p[2], p[3], p[4], p[5]);
    return str;
}

static void update_device_info(esp_bt_gap_cb_param_t *param)
{
    char bda_str[18];
    uint32_t cod = 0;
    int32_t rssi = -129; /* invalid value */
    esp_bt_gap_dev_prop_t *p;

    //ESP_LOGI(GAP_TAG, "Device found: %s", bda2str(param->disc_res.bda, bda_str, 18));
    bda2str(param->disc_res.bda, bda_str, 18);
    for (int i = 0; i < param->disc_res.num_prop; i++) {
        p = param->disc_res.prop + i;
        switch (p->type) {
        case ESP_BT_GAP_DEV_PROP_COD:
            cod = *(uint32_t *)(p->val);
            //ESP_LOGI(GAP_TAG, "--Class of Device: 0x%x", cod);
            break;
        case ESP_BT_GAP_DEV_PROP_RSSI:
            rssi = *(int8_t *)(p->val);
            //ESP_LOGI(GAP_TAG, "--RSSI: %d", rssi);
            break;
        case ESP_BT_GAP_DEV_PROP_BDNAME:
        default:
            break;
        }
    }

    //Add the information to the char array

    char *s;

    // this will just output the length which is to expect
    int length = snprintf( NULL, 0, "%d", rssi );

    char* rssiValueAsString = malloc( length + 1 );// one more for 0-terminator
    snprintf( rssiValueAsString, length + 1, "%d", rssi );

    s = strstr(btSsid, bda_str);      // search for string "hassasin" in buff
    if (s == NULL)                    // if successful then s now points at "hassasin"
    {
        strcat(btSsid, bda_str);
        strcat(btSsid, "=");
        strcat(btSsid, rssiValueAsString);
        strcat(btSsid, ";");
    }
}

// AES References: https://everythingesp.com/esp32-arduino-tutorial-encryption-aes128-in-ecb-mode/
// Library Documentation: https://tls.mbed.org/kb/how-to/encrypt-with-aes-cbc

#define AES_TAG "AES"

void encrypt_rssi(char * plainText, unsigned char * outputBuffer){
    unsigned char iv[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    unsigned char key[32] = "7fkgy8fhsk7wmwfs0fhekcm38dhtusn3"; // Assume preshared key
    //ESP_LOGI(SOCKET_TAG, "unencrypted data len: %d", strlen(plainText));
    //ESP_LOGI(SOCKET_TAG, "unencrypted data: %s", plainText);

    mbedtls_aes_context aes;

    mbedtls_aes_init( &aes );
    mbedtls_aes_setkey_enc( &aes, key, 256 );
    mbedtls_aes_crypt_cbc( &aes, MBEDTLS_AES_ENCRYPT, strlen(plainText), iv, (const unsigned char*)plainText, outputBuffer );
    mbedtls_aes_free( &aes );
}

// Function to send info using sockets
void send_devices_and_rssi(unsigned char * data, int ciphertxt_length) {
    ESP_LOGI(SOCKET_TAG, "start");

    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ESP_LOGI(SOCKET_TAG, "socket: rc: %d", sock);

    struct sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    inet_pton(AF_INET, SERVER_IP, &serverAddress.sin_addr.s_addr);
    serverAddress.sin_port = htons(SERVER_PORT);

    int rc = connect(sock, (struct sockaddr *)&serverAddress, sizeof(struct sockaddr_in));
    ESP_LOGI(SOCKET_TAG, "connect rc: %d", rc);
    ESP_LOGI(SOCKET_TAG, "trying to send: %s", data);

    //ESP_LOGI(SOCKET_TAG, "sending data sizes are: %d %d", 8*sizeof(data), ciphertxt_length);

    //Send encrypted btSsid as "data"
    rc = send(sock, data, ciphertxt_length, 0);
    ESP_LOGI(SOCKET_TAG, "send: rc: %d", rc);

    rc = close(sock);
    ESP_LOGI(SOCKET_TAG, "close: rc: %d", rc);
}

void bt_app_gap_init(void)
{
    app_gap_cb_t *p_dev = &m_dev_info;
    memset(p_dev, 0, sizeof(app_gap_cb_t));
}

void bt_app_gap_cb(esp_bt_gap_cb_event_t event, esp_bt_gap_cb_param_t *param)
{
    app_gap_cb_t *p_dev = &m_dev_info;

    switch (event) {
    case ESP_BT_GAP_DISC_RES_EVT: {
        update_device_info(param);
        break;
    }
    case ESP_BT_GAP_DISC_STATE_CHANGED_EVT: {
        if (param->disc_st_chg.state == ESP_BT_GAP_DISCOVERY_STOPPED && isStarted == 1) {
            ESP_LOGI(GAP_TAG, "Devices found: %s", btSsid);
            // Here we need to send the Devices found and RSSI information to the Raspberry Pi control node
            if (btSsid[0] != 0) { // If not empty, we have data to send
                // First encrypt it and then send
                // Make sure plainText is multiple of 16 bytes
                char space[2] = " ";
                while (strlen(btSsid) % 16 != 0) {
                    // https://stackoverflow.com/a/34055805
                    strcat(btSsid, space);
                }
                int ciphertxt_length = strlen(btSsid);
                unsigned char cipherTextOutput[ciphertxt_length];

                encrypt_rssi(btSsid, cipherTextOutput);
                /*for (int i = 0; i < ciphertxt_length; i++) {
                    ESP_LOGI(AES_TAG, "%02x %02x", (int)btSsid[i], (int)cipherTextOutput[i]);
                }
                ESP_LOGI(SOCKET_TAG, "encrypted data len: %d %d", sizeof(cipherTextOutput), ciphertxt_length);
                ESP_LOGI(SOCKET_TAG, "encrypted data: %s", cipherTextOutput);*/

                send_devices_and_rssi(cipherTextOutput, ciphertxt_length);
            }

            ESP_LOGI(GAP_TAG, "Device discovery stopped.");

            //Release memory
            esp_bt_gap_cancel_discovery();
            esp_bt_controller_mem_release(ESP_BT_MODE_BTDM);

            //Clear the char array
            memset(btSsid, 0, sizeof(btSsid));

            /* Start another discovery */
            esp_bt_gap_start_discovery(ESP_BT_INQ_MODE_GENERAL_INQUIRY, 1, 0);
            isStarted = 0;
        } else if (param->disc_st_chg.state == ESP_BT_GAP_DISCOVERY_STARTED) {
            ESP_LOGI(GAP_TAG, "Discovery started.");
            isStarted = 1;
        }
        break;
    }
    case ESP_BT_GAP_RMT_SRVC_REC_EVT:
    default: {
        ESP_LOGI(GAP_TAG, "event: %d", event);
        break;
    }
    }
    return;
}

void bt_app_gap_start_up(void)
{
    /* register GAP callback function */
    esp_bt_gap_register_callback(bt_app_gap_cb);

    /* inititialize device information and status */
    app_gap_cb_t *p_dev = &m_dev_info;
    memset(p_dev, 0, sizeof(app_gap_cb_t));

    /* start to discover nearby Bluetooth devices */
    p_dev->state = APP_GAP_STATE_DEVICE_DISCOVERING;
    esp_bt_gap_start_discovery(ESP_BT_INQ_MODE_LIMITED_INQUIRY, 1, 0);
}

void app_main()
{
    /* Initialize NVS — it is used to store PHY calibration data */
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK( ret );

    // Initialize Wifi
    ESP_LOGI(TAG, "ESP_WIFI_MODE_STA");
    wifi_init_sta();

    esp_bt_controller_config_t bt_cfg = BT_CONTROLLER_INIT_CONFIG_DEFAULT();
    if (esp_bt_controller_init(&bt_cfg) != ESP_OK) {
        ESP_LOGE(GAP_TAG, "%s initialize controller failed\n", __func__);
        return;
    }

    if (esp_bt_controller_enable(ESP_BT_MODE_CLASSIC_BT) != ESP_OK) {
        ESP_LOGE(GAP_TAG, "%s enable controller failed\n", __func__);
        return;
    }

    if (esp_bluedroid_init() != ESP_OK) {
        ESP_LOGE(GAP_TAG, "%s initialize bluedroid failed\n", __func__);
        return;
    }

    if (esp_bluedroid_enable() != ESP_OK) {
        ESP_LOGE(GAP_TAG, "%s enable bluedroid failed\n", __func__);
        return;
    }

    bt_app_gap_start_up();
}
