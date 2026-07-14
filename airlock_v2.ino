#include <WiFi.h>
#include "esp_wifi.h"
#include <BLEDevice.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>
#include <ArduinoJson.h>

// ================= CONFIG =================
#define LED_ALERTA 2
#define DEVICE_ID "AIRLOCK_NODE_01"
#define JSON_INTERVAL 500     // Enviar JSON cada 500ms (ajustable)
#define MAX_BUFFER 30

// ================= ESTRUCTURAS =================
typedef struct {
  uint8_t mac[6];
  int rssi;
  uint8_t canal;
  bool esDeauth;
  unsigned long timestamp;
} DispositivoDetectado;

// ================= VARIABLES =================
DispositivoDetectado buffer[MAX_BUFFER];
int bufferIndex = 0;

int canalActual = 1;
const int maxCanales = 13;

unsigned long ultimoJSON = 0;
unsigned long ultimoContador = 0;

int dispositivosWiFi = 0;
int deauthCount = 0;
int bleCount = 0;

BLEScan* pBLEScan;

// ================= FUNCIONES =================
void printMAC(uint8_t* mac) {
  for (int i = 0; i < 6; i++) {
    Serial.printf("%02X", mac[i]);
    if (i < 5) Serial.print(":");
  }
}

void enviarJSON(const DispositivoDetectado& d) {
  StaticJsonDocument<256> doc;
  doc["id"] = DEVICE_ID;
  doc["mac"] = String(d.mac[0], HEX) + ":" +
               String(d.mac[1], HEX) + ":" +
               String(d.mac[2], HEX) + ":" +
               String(d.mac[3], HEX) + ":" +
               String(d.mac[4], HEX) + ":" +
               String(d.mac[5], HEX);
  doc["rssi"] = d.rssi;
  doc["canal"] = d.canal;
  doc["deauth"] = d.esDeauth ? 1 : 0;
  doc["time"] = d.timestamp;

  serializeJson(doc, Serial);
  Serial.println();        // Nueva línea al final (importante para Python)
}

// ================= SNIFFER WIFI =================
void sniffer(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT) return;

  wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
  if (pkt->rx_ctrl.sig_len < 24) return;   // mínimo para management frame

  DispositivoDetectado d;
  uint8_t* mac_sa = pkt->payload + 10;     // Dirección fuente en management frames

  memcpy(d.mac, mac_sa, 6);
  d.rssi = pkt->rx_ctrl.rssi;
  d.canal = canalActual;
  d.timestamp = millis();

  uint8_t subtype = pkt->payload[0] & 0xF0;
  d.esDeauth = (subtype == 0xC0 || subtype == 0xA0);  // Deauth o Disassoc

  dispositivosWiFi++;

  if (d.esDeauth) {
    deauthCount++;
    digitalWrite(LED_ALERTA, HIGH);
    Serial.println("\n🚨 ATAQUE DEAUTH DETECTADO 🚨");
    Serial.print("MAC: ");
    printMAC(d.mac);
    Serial.printf(" | Canal: %d | RSSI: %d\n\n", d.canal, d.rssi);
    delay(150);
    digitalWrite(LED_ALERTA, LOW);

    enviarJSON(d);        // Enviar inmediatamente si es deauth
  } else {
    // Guardar en buffer para envío periódico
    if (bufferIndex < MAX_BUFFER) {
      buffer[bufferIndex++] = d;
    }
  }
}

// ================= TAREA WIFI =================
void wifiTask(void * pvParameters) {
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  esp_wifi_init(&cfg);
  esp_wifi_set_storage(WIFI_STORAGE_RAM);
  esp_wifi_set_mode(WIFI_MODE_NULL);
  esp_wifi_start();
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(sniffer);

  Serial.println("✅ WiFi Sniffer activo (Core 0)");

  while (true) {
    esp_wifi_set_channel(canalActual, WIFI_SECOND_CHAN_NONE);
    canalActual = (canalActual % maxCanales) + 1;
    vTaskDelay(pdMS_TO_TICKS(250));   // Cambiado a 250ms
  }
}

// ================= BLE CALLBACK =================
class MyBLECallback : public BLEAdvertisedDeviceCallbacks {
  void onResult(BLEAdvertisedDevice device) {
    bleCount++;
    // Opcional: enviar también BLE como JSON
    StaticJsonDocument<200> doc;
    doc["id"] = DEVICE_ID;
    doc["mac"] = device.getAddress().toString();
    doc["rssi"] = device.getRSSI();
    doc["type"] = "BLE";
    serializeJson(doc, Serial);
    Serial.println();
  }
};

// ================= TAREA BLE =================
void bleTask(void * pvParameters) {
  BLEDevice::init("");
  pBLEScan = BLEDevice::getScan();
  pBLEScan->setAdvertisedDeviceCallbacks(new MyBLECallback());
  pBLEScan->setActiveScan(false);
  pBLEScan->setInterval(100);
  pBLEScan->setWindow(99);

  Serial.println("✅ BLE Scanner activo (Core 1)");

  while (true) {
    pBLEScan->start(4, false);
    pBLEScan->clearResults();
    vTaskDelay(pdMS_TO_TICKS(2000));
  }
}

// ================= SETUP =================
void setup() {
  Serial.begin(115200);
  pinMode(LED_ALERTA, OUTPUT);
  digitalWrite(LED_ALERTA, LOW);

  Serial.println("\n=== AIRLOCK v3.1 - Mejorado ===");
  Serial.println("WiFi Sniffer + BLE + JSON estable\n");

  esp_log_level_set("wifi", ESP_LOG_NONE);

  xTaskCreatePinnedToCore(wifiTask, "WiFiTask", 8192, NULL, 1, NULL, 0);
  delay(500);
  xTaskCreatePinnedToCore(bleTask, "BLETask", 8192, NULL, 1, NULL, 1);
}

// ================= LOOP =================
void loop() {
  // Enviar JSON del buffer periódicamente
  if (millis() - ultimoJSON > JSON_INTERVAL && bufferIndex > 0) {
    for (int i = 0; i < bufferIndex; i++) {
      enviarJSON(buffer[i]);
    }
    bufferIndex = 0;
    ultimoJSON = millis();
  }

  // Resumen cada minuto
  if (millis() - ultimoContador > 60000) {
    Serial.printf("📈 [RESUMEN] WiFi: %d | Deauth: %d | BLE: %d\n", 
                  dispositivosWiFi, deauthCount, bleCount);
    dispositivosWiFi = deauthCount = bleCount = 0;
    ultimoContador = millis();
  }

  delay(10);
}