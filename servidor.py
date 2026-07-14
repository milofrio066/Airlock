# ============================================================
#  Airlock — servidor.py  v3.1
#  Motor: Flask + Scikit-learn + HMAC + Respuesta Automatica
# ============================================================

from flask import Flask, jsonify, request, Response
import serial
import json
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import threading
import time
import io
import os
import hmac
import hashlib
import csv
import random          # Para modo demo sin hardware
import string

# ── Scikit-learn ─────────────────────────────────────────────
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
import warnings
warnings.filterwarnings("ignore")

app = Flask(__name__)

# ============================================================
#  CONFIGURACIÓN GLOBAL
# ============================================================
SERIAL_PORT          = "COM3"
BAUD_RATE            = 115200
HMAC_SECRET          = b"airlock-secret-2025"
WHITELIST_FILE       = "whitelist.txt"
BLACKLIST_FILE       = "blacklist.txt"
LOG_FILE             = "airlock_log.csv"
AUTO_BLOCK_THRESHOLD = 3
RETRAIN_INTERVAL     = 50
DEMO_MODE            = True      # ← Activa datos sintéticos si no hay ESP32

# ── Estado global ─────────────────────────────────────────────
df = pd.DataFrame(columns=[
    "timestamp", "device_id", "mac", "rssi",
    "canal", "deauth", "type", "riesgo_ia",
    "en_whitelist", "en_blacklist", "hmac_ok"
])

nivel_amenaza     = 0
alertas_historial = []
whitelist         = set()
blacklist         = set()
deauth_counter    = {}
modelo_ia         = None
label_encoder     = LabelEncoder()
modelo_entrenado  = False
ser_global        = None
serial_conectado  = False

# ============================================================
#  1. PERSISTENCIA — Whitelist / Blacklist / Log CSV
# ============================================================

def cargar_set(filepath):
    if os.path.exists(filepath):
        with open(filepath, "r") as f:
            return set(line.strip().upper() for line in f if line.strip())
    return set()

def guardar_set(filepath, conjunto):
    with open(filepath, "w") as f:
        for item in sorted(conjunto):
            f.write(item + "\n")

def guardar_registro_csv(registro):
    file_exists = os.path.exists(LOG_FILE)
    try:
        with open(LOG_FILE, "a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=registro.keys())
            if not file_exists:
                writer.writeheader()
            writer.writerow(registro)
    except Exception as e:
        print(f"[CSV] Error guardando: {e}")

whitelist = cargar_set(WHITELIST_FILE)
blacklist = cargar_set(BLACKLIST_FILE)

# ============================================================
#  2. PROTOCOLO SEGURO — Validación HMAC-SHA256
# ============================================================

def validar_hmac(payload_str: str, firma_recibida: str):
    if not firma_recibida:
        return None
    try:
        firma_esperada = hmac.new(
            HMAC_SECRET,
            payload_str.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(firma_esperada, firma_recibida)
    except Exception:
        return False

# ============================================================
#  3. MODELO DE INTELIGENCIA ARTIFICIAL — Random Forest
# ============================================================

def extraer_features(df_input):
    features = pd.DataFrame()
    features["rssi_norm"]      = df_input["rssi"].fillna(-100).clip(-100, 0) / -100
    features["es_deauth"]      = df_input["deauth"].astype(int)
    features["es_ble"]         = (df_input["type"].str.upper() == "BLE").astype(int)
    features["canal_norm"]     = df_input["canal"].fillna(0).astype(float) / 13.0
    features["en_blacklist"]   = df_input["mac"].apply(lambda m: 1 if str(m).upper() in blacklist else 0)
    features["en_whitelist"]   = df_input["mac"].apply(lambda m: 1 if str(m).upper() in whitelist else 0)
    freq = df_input["mac"].value_counts().to_dict()
    features["frecuencia_mac"] = df_input["mac"].map(freq).fillna(1)
    features["deauths_mac"]    = df_input["mac"].apply(
        lambda m: deauth_counter.get(str(m).upper(), 0)
    )
    return features

def generar_etiqueta_riesgo(row):
    score = 0
    if row.get("deauth", False):                   score += 3
    if row.get("mac", "").upper() in blacklist:    score += 3
    rssi = row.get("rssi", -100)
    if rssi is not None and rssi > -40:            score += 1
    if row.get("mac", "").upper() not in whitelist and \
       row.get("type", "WiFi").upper() == "WIFI":  score += 1
    deauths = deauth_counter.get(str(row.get("mac","")).upper(), 0)
    if deauths >= 5:   score += 2
    elif deauths >= 2: score += 1
    return min(score, 3)

def entrenar_modelo():
    global modelo_ia, modelo_entrenado

    if len(df) < 20:
        return False

    try:
        df_train         = df.copy()
        df_train["label"] = df_train.apply(generar_etiqueta_riesgo, axis=1)

        if df_train["label"].nunique() < 2:
            return False

        X = extraer_features(df_train)
        y = df_train["label"]

        modelo_ia = RandomForestClassifier(
            n_estimators=100,
            max_depth=6,
            random_state=42,
            class_weight="balanced"
        )
        modelo_ia.fit(X, y)
        modelo_entrenado = True
        print(f"[IA] Modelo entrenado con {len(df_train)} muestras — "
              f"Clases: {sorted(df_train['label'].unique())}")
        registrar_alerta("SISTEMA", f"Modelo IA reentrenado con {len(df_train)} muestras")
        return True

    except Exception as e:
        print(f"[IA] Error entrenando modelo: {e}")
        return False

def predecir_riesgo(registro: dict) -> int:
    global modelo_ia, modelo_entrenado

    if not modelo_entrenado or modelo_ia is None:
        return generar_etiqueta_riesgo(registro)

    try:
        df_single = pd.DataFrame([registro])
        X         = extraer_features(df_single)
        pred      = modelo_ia.predict(X)[0]
        return int(pred)
    except Exception:
        return generar_etiqueta_riesgo(registro)

def importancia_features():
    if not modelo_entrenado or modelo_ia is None:
        return {}
    nombres = ["rssi_norm","es_deauth","es_ble","canal_norm",
               "en_blacklist","en_whitelist","frecuencia_mac","deauths_mac"]
    importancias = modelo_ia.feature_importances_
    return {n: round(float(v), 4) for n, v in zip(nombres, importancias)}

# ============================================================
#  4. RESPUESTA AUTOMÁTICA ANTE AMENAZAS
# ============================================================

NIVELES_TEXTO = ["BAJO", "MEDIO", "ALTO", "CRÍTICO"]

def respuesta_automatica(registro: dict, riesgo: int):
    mac = str(registro.get("mac", "")).upper()

    if riesgo == 1:
        registrar_alerta("ADVERTENCIA",
            f"Dispositivo sospechoso detectado (Nivel Medio): {mac}", mac)

    elif riesgo == 2:
        registrar_alerta("ALTO",
            f"Actividad de alto riesgo detectada en: {mac}", mac)
        deauth_counter[mac] = deauth_counter.get(mac, 0) + 1

    elif riesgo == 3:
        registrar_alerta("CRITICO",
            f"AMENAZA CRÍTICA detectada — Auto-bloqueando: {mac}", mac)
        # Solo auto-bloquear si supera el umbral de deauths
        if deauth_counter.get(mac, 0) >= AUTO_BLOCK_THRESHOLD:
            blacklist.add(mac)
            guardar_set(BLACKLIST_FILE, blacklist)
            enviar_comando_esp32({"cmd": "block", "mac": mac})
            registrar_alerta("SISTEMA",
                f"MAC {mac} agregada automáticamente a blacklist "
                f"({deauth_counter.get(mac,0)} deauths)", mac)

def enviar_comando_esp32(comando: dict):
    global ser_global
    if ser_global and ser_global.is_open:
        try:
            msg = json.dumps(comando) + "\n"
            ser_global.write(msg.encode("utf-8"))
            print(f"[ESP32 CMD] Enviado: {msg.strip()}")
        except Exception as e:
            print(f"[ESP32 CMD] Error enviando: {e}")
    else:
        print(f"[ESP32 CMD] (sin serial) Comando: {comando}")

# ============================================================
#  5. MODO DEMO — Generación de datos sintéticos
# ============================================================

MACS_DEMO = [
    "AA:BB:CC:11:22:33",
    "DE:AD:BE:EF:CA:FE",
    "11:22:33:44:55:66",
    "FF:EE:DD:CC:BB:AA",
    "12:34:56:78:9A:BC",
    "CA:FE:BA:BE:00:01",
    "00:11:22:33:44:55",
    "A0:B0:C0:D0:E0:F0",
]

def generar_registro_demo():
    """Genera un registro de red sintético para demostración."""
    mac     = random.choice(MACS_DEMO)
    es_ble  = random.random() < 0.2
    deauth  = random.random() < 0.08          # 8% probabilidad
    rssi    = random.randint(-90, -30)
    canal   = random.choice([1, 6, 11]) if not es_ble else 37

    return {
        "mac":    mac,
        "rssi":   rssi,
        "canal":  canal,
        "deauth": deauth,
        "type":   "BLE" if es_ble else "WiFi",
        "id":     f"demo_{random.randint(1000,9999)}"
    }

def hilo_demo():
    """Genera datos demo cuando no hay ESP32 conectado."""
    global df
    print("[Demo] Iniciando generador de datos sintéticos...")
    registrar_alerta("SISTEMA", "Modo DEMO activo — Datos sintéticos (sin ESP32)")
    contador = 0

    while True:
        try:
            data   = generar_registro_demo()
            mac    = data["mac"].upper()
            en_wl  = mac in whitelist
            en_bl  = mac in blacklist

            registro = {
                "timestamp":    datetime.now().isoformat(),
                "device_id":    data.get("id"),
                "mac":          mac,
                "rssi":         data.get("rssi"),
                "canal":        data.get("canal"),
                "deauth":       bool(data.get("deauth", False)),
                "type":         data.get("type", "WiFi"),
                "riesgo_ia":    0,
                "en_whitelist": en_wl,
                "en_blacklist": en_bl,
                "hmac_ok":      "N/A"
            }

            if registro["deauth"]:
                deauth_counter[mac] = deauth_counter.get(mac, 0) + 1

            riesgo           = predecir_riesgo(registro)
            registro["riesgo_ia"] = riesgo

            df = pd.concat([df, pd.DataFrame([registro])], ignore_index=True)
            # Limitar el DataFrame a 5000 filas para no saturar memoria
            if len(df) > 5000:
                df = df.tail(4000).reset_index(drop=True)

            guardar_registro_csv(registro)
            contador += 1

            respuesta_automatica(registro, riesgo)

            if contador % 6 == 0:
                nivel_antes = nivel_amenaza
                calcular_nivel_global()
                if nivel_amenaza != nivel_antes:
                    registrar_alerta("SISTEMA",
                        f"Nivel de amenaza global: {NIVELES_TEXTO[nivel_amenaza]}")

            if contador % RETRAIN_INTERVAL == 0:
                threading.Thread(target=entrenar_modelo, daemon=True).start()

            time.sleep(random.uniform(0.8, 2.5))     # Velocidad de demo

        except Exception as e:
            print(f"[Demo] Error: {e}")
            time.sleep(2)

# ============================================================
#  6. RUTAS FLASK — API REST
# ============================================================

@app.route('/')
def index():
    try:
        with open('dashboard.html', 'r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        return "<h1>Error: dashboard.html no encontrado</h1><p>Asegúrate de que dashboard.html está en el mismo directorio que servidor.py</p>", 404

@app.route('/api/data')
def get_data():
    mac_filter   = request.args.get('mac', '').strip().upper()
    tipo_filter  = request.args.get('type', '').strip()
    deauth_only  = request.args.get('deauth_only', 'false').lower() == 'true'
    riesgo_min   = int(request.args.get('riesgo_min', 0))

    temp = df.copy() if not df.empty else pd.DataFrame()

    if not temp.empty:
        if mac_filter:
            temp = temp[temp['mac'].str.upper().str.contains(mac_filter, na=False)]
        if tipo_filter:
            temp = temp[temp['type'].str.lower() == tipo_filter.lower()]
        if deauth_only:
            temp = temp[temp['deauth'] == True]
        if riesgo_min > 0 and 'riesgo_ia' in temp.columns:
            temp = temp[temp['riesgo_ia'] >= riesgo_min]
        registros = temp.tail(200).to_dict('records')
    else:
        registros = []

    # Serializar correctamente timestamps y booleans
    for r in registros:
        for k, v in r.items():
            if isinstance(v, (pd.Timestamp, datetime)):
                r[k] = v.isoformat()
            elif isinstance(v, float) and np.isnan(v):
                r[k] = None
            elif hasattr(v, 'item'):
                r[k] = v.item()

    total_deauths = int(df['deauth'].sum()) if not df.empty else 0
    macs_unicas   = df['mac'].nunique()     if not df.empty else 0
    en_wl_count   = sum(1 for m in df['mac'].unique() if str(m).upper() in whitelist) if not df.empty else 0

    return jsonify({
        "nivel_amenaza":      nivel_amenaza,
        "total_registros":    len(df),
        "total_deauths":      total_deauths,
        "macs_unicas":        macs_unicas,
        "en_whitelist":       en_wl_count,
        "en_blacklist":       len(blacklist),
        "modelo_activo":      modelo_entrenado,
        "ia_muestras":        len(df),
        "serial_ok":          serial_conectado,
        "demo_mode":          DEMO_MODE,
        "ultimos_registros":  registros,
        "whitelist":          sorted(list(whitelist)),
        "blacklist":          sorted(list(blacklist))
    })

@app.route('/api/chart')
def get_chart():
    if df.empty:
        return jsonify({"labels": [], "deauths": [], "total": [], "riesgo_alto": []})

    try:
        temp = df.copy()
        temp['timestamp_dt'] = pd.to_datetime(temp['timestamp'], errors='coerce')
        ahora  = datetime.now()
        limite = ahora - timedelta(minutes=30)
        temp   = temp[temp['timestamp_dt'] > limite]
        temp['minuto'] = temp['timestamp_dt'].dt.floor('min')

        minutos_rango = pd.date_range(
            start=limite.replace(second=0, microsecond=0),
            end=ahora.replace(second=0, microsecond=0),
            freq='min'
        )
        base = pd.DataFrame({'minuto': minutos_rango})

        deauths_df = temp[temp['deauth'] == True].groupby('minuto').size().reset_index(name='deauths')
        total_df   = temp.groupby('minuto').size().reset_index(name='total')

        merged = base \
            .merge(deauths_df, on='minuto', how='left') \
            .merge(total_df,   on='minuto', how='left') \
            .fillna(0)

        return jsonify({
            "labels":  [m.strftime('%H:%M') for m in merged['minuto']],
            "deauths": [int(v) for v in merged['deauths']],
            "total":   [int(v) for v in merged['total']]
        })
    except Exception as e:
        print(f"[Chart] Error: {e}")
        return jsonify({"labels": [], "deauths": [], "total": []})

@app.route('/api/alerts')
def get_alerts():
    nivel_filter = request.args.get('nivel', '').upper()
    lista = alertas_historial[-500:]
    if nivel_filter:
        lista = [a for a in lista if a['nivel'] == nivel_filter]
    return jsonify({"alertas": list(reversed(lista))})

@app.route('/api/ia/status')
def ia_status():
    return jsonify({
        "entrenado":    modelo_entrenado,
        "muestras":     len(df),
        "muestras_min": 20,
        "importancias": importancia_features(),
        "clases":       ["Bajo", "Medio", "Alto", "Crítico"]
    })

@app.route('/api/ia/retrain', methods=['POST'])
def ia_retrain():
    exito = entrenar_modelo()
    return jsonify({
        "ok":           exito,
        "modelo_activo": modelo_entrenado,
        "muestras":     len(df)
    })

@app.route('/api/export')
def export_csv():
    mac_filter  = request.args.get('mac', '').strip().upper()
    deauth_only = request.args.get('deauth_only', 'false').lower() == 'true'
    temp = df.copy()
    if not temp.empty:
        if mac_filter:
            temp = temp[temp['mac'].str.upper().str.contains(mac_filter, na=False)]
        if deauth_only:
            temp = temp[temp['deauth'] == True]
    output = io.StringIO()
    temp.to_csv(output, index=False)
    output.seek(0)
    fname = f"airlock_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={"Content-Disposition": f"attachment; filename={fname}"}
    )

# ── Whitelist ─────────────────────────────────────────────────
@app.route('/api/whitelist', methods=['GET'])
def get_whitelist():
    return jsonify({"whitelist": sorted(list(whitelist))})

@app.route('/api/whitelist/add', methods=['POST'])
def add_whitelist():
    data = request.get_json()
    if not data:
        return jsonify({"error": "JSON requerido"}), 400
    mac = data.get('mac', '').strip().upper()
    if not mac:
        return jsonify({"error": "MAC requerida"}), 400
    # Validar formato básico
    if len(mac) != 17 or mac.count(':') != 5:
        return jsonify({"error": "Formato inválido (AA:BB:CC:DD:EE:FF)"}), 400
    whitelist.add(mac)
    blacklist.discard(mac)
    guardar_set(WHITELIST_FILE, whitelist)
    guardar_set(BLACKLIST_FILE, blacklist)
    registrar_alerta("INFO", f"MAC {mac} autorizada en whitelist", mac)
    enviar_comando_esp32({"cmd": "allow", "mac": mac})
    return jsonify({
        "ok":        True,
        "mac":       mac,
        "whitelist": sorted(list(whitelist))
    })

@app.route('/api/whitelist/remove', methods=['POST'])
def remove_whitelist():
    data = request.get_json()
    if not data:
        return jsonify({"error": "JSON requerido"}), 400
    mac = data.get('mac', '').strip().upper()
    whitelist.discard(mac)
    guardar_set(WHITELIST_FILE, whitelist)
    registrar_alerta("INFO", f"MAC {mac} removida de whitelist", mac)
    return jsonify({
        "ok":        True,
        "mac":       mac,
        "whitelist": sorted(list(whitelist))
    })

# ── Blacklist ─────────────────────────────────────────────────
@app.route('/api/blacklist', methods=['GET'])
def get_blacklist():
    return jsonify({"blacklist": sorted(list(blacklist))})

@app.route('/api/blacklist/add', methods=['POST'])
def add_blacklist():
    data = request.get_json()
    if not data:
        return jsonify({"error": "JSON requerido"}), 400
    mac = data.get('mac', '').strip().upper()
    if not mac:
        return jsonify({"error": "MAC requerida"}), 400
    if len(mac) != 17 or mac.count(':') != 5:
        return jsonify({"error": "Formato inválido (AA:BB:CC:DD:EE:FF)"}), 400
    blacklist.add(mac)
    whitelist.discard(mac)
    guardar_set(BLACKLIST_FILE, blacklist)
    guardar_set(WHITELIST_FILE, whitelist)
    registrar_alerta("CRITICO", f"MAC {mac} bloqueada manualmente", mac)
    enviar_comando_esp32({"cmd": "block", "mac": mac})
    return jsonify({
        "ok":        True,
        "mac":       mac,
        "blacklist": sorted(list(blacklist))
    })

@app.route('/api/blacklist/remove', methods=['POST'])
def remove_blacklist():
    data = request.get_json()
    if not data:
        return jsonify({"error": "JSON requerido"}), 400
    mac = data.get('mac', '').strip().upper()
    blacklist.discard(mac)
    guardar_set(BLACKLIST_FILE, blacklist)
    registrar_alerta("INFO", f"MAC {mac} removida de blacklist", mac)
    return jsonify({
        "ok":        True,
        "mac":       mac,
        "blacklist": sorted(list(blacklist))
    })

# ── Status general ────────────────────────────────────────────
@app.route('/api/status')
def get_status():
    return jsonify({
        "serial_conectado": serial_conectado,
        "serial_port":      SERIAL_PORT,
        "demo_mode":        DEMO_MODE,
        "modelo_entrenado": modelo_entrenado,
        "total_registros":  len(df),
        "total_alertas":    len(alertas_historial),
        "whitelist_size":   len(whitelist),
        "blacklist_size":   len(blacklist),
        "nivel_amenaza":    nivel_amenaza,
        "uptime":           datetime.now().isoformat()
    })

# ── Enviar comando manual al ESP32 ────────────────────────────
@app.route('/api/esp32/cmd', methods=['POST'])
def esp32_cmd():
    data = request.get_json()
    if not data or 'cmd' not in data:
        return jsonify({"error": "cmd requerido"}), 400
    enviar_comando_esp32(data)
    return jsonify({"ok": True, "cmd": data})

# ============================================================
#  7. HELPERS INTERNOS
# ============================================================

def registrar_alerta(nivel, mensaje, mac=""):
    entrada = {
        "timestamp": datetime.now().isoformat(),
        "nivel":     nivel,
        "mensaje":   mensaje,
        "mac":       mac
    }
    alertas_historial.append(entrada)
    # Limitar historial a 1000 alertas
    if len(alertas_historial) > 1000:
        del alertas_historial[:200]
    print(f"[{nivel}] {mensaje}")

def calcular_nivel_global():
    global nivel_amenaza
    if df.empty:
        return

    try:
        temp = df.copy()
        temp['ts'] = pd.to_datetime(temp['timestamp'], errors='coerce')
        reciente = temp[temp['ts'] > (datetime.now() - timedelta(minutes=5))]

        if reciente.empty:
            return

        if 'riesgo_ia' in reciente.columns:
            avg_riesgo = reciente['riesgo_ia'].mean()
            max_riesgo = reciente['riesgo_ia'].max()
            deauths    = int(reciente['deauth'].sum())
            score = (max_riesgo * 0.5) + (avg_riesgo * 0.3) + (min(deauths / 5, 1) * 3 * 0.2)
            nivel_amenaza = min(int(score), 3)
        else:
            deauths = int(reciente['deauth'].sum())
            unicos  = reciente['mac'].nunique()
            score   = 0
            if deauths >= 8:  score += 3
            elif deauths >= 3: score += 2
            if unicos > 40:   score += 1
            nivel_amenaza = min(score, 3)
    except Exception as e:
        print(f"[Nivel] Error calculando: {e}")

# ============================================================
#  8. HILO SERIAL — Lectura continua del ESP32
# ============================================================

def procesar_dato(data: dict, hmac_valido):
    """Procesa un registro de datos del ESP32 o demo."""
    global df

    mac   = str(data.get("mac", "")).upper()
    en_wl = mac in whitelist
    en_bl = mac in blacklist

    registro = {
        "timestamp":    datetime.now().isoformat(),
        "device_id":    data.get("id"),
        "mac":          mac,
        "rssi":         data.get("rssi"),
        "canal":        data.get("canal"),
        "deauth":       bool(data.get("deauth", False)),
        "type":         data.get("type", "WiFi"),
        "riesgo_ia":    0,
        "en_whitelist": en_wl,
        "en_blacklist": en_bl,
        "hmac_ok":      hmac_valido if hmac_valido is not None else "N/A"
    }

    if registro["deauth"]:
        deauth_counter[mac] = deauth_counter.get(mac, 0) + 1

    riesgo                = predecir_riesgo(registro)
    registro["riesgo_ia"] = riesgo

    df = pd.concat([df, pd.DataFrame([registro])], ignore_index=True)
    if len(df) > 5000:
        df = df.tail(4000).reset_index(drop=True)

    guardar_registro_csv(registro)
    return registro, riesgo

def leer_serial():
    global ser_global, serial_conectado

    print(f"[Serial] Conectando al ESP32 en {SERIAL_PORT}...")
    contador = 0

    try:
        ser_global      = serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=0.5)
        serial_conectado = True
        print("[Serial] Puerto abierto correctamente ✓")
        registrar_alerta("SISTEMA", f"ESP32 conectado en {SERIAL_PORT}")

        while True:
            linea_bytes = ser_global.readline()
            if len(linea_bytes) == 0:
                time.sleep(0.01)
                continue

            linea = linea_bytes.decode('utf-8', errors='ignore').strip()
            if not linea or not linea.startswith('{'):
                continue

            print(f"[Serial] RX: {linea[:120]}")

            try:
                data  = json.loads(linea)
                firma = data.pop("hmac", None)
                payload_str = json.dumps(data, sort_keys=True)
                hmac_valido = validar_hmac(payload_str, firma)

                if hmac_valido is False:
                    registrar_alerta("CRITICO",
                        "Mensaje rechazado: firma HMAC inválida (posible spoofing)",
                        data.get("mac","?"))
                    continue

                registro, riesgo = procesar_dato(data, hmac_valido)
                contador += 1
                print(f"[IA] MAC: {registro['mac']} → Riesgo: {['Bajo','Medio','Alto','Crítico'][riesgo]}")

                respuesta_automatica(registro, riesgo)

                if contador % 6 == 0:
                    nivel_antes = nivel_amenaza
                    calcular_nivel_global()
                    if nivel_amenaza != nivel_antes:
                        registrar_alerta("SISTEMA",
                            f"Nivel de amenaza: {NIVELES_TEXTO[nivel_amenaza]}")

                if contador % RETRAIN_INTERVAL == 0:
                    threading.Thread(target=entrenar_modelo, daemon=True).start()

            except json.JSONDecodeError as e:
                print(f"[Serial] JSON inválido: {e}")
            except Exception as e:
                print(f"[Serial] Error procesando: {e}")

    except serial.SerialException as e:
        serial_conectado = False
        print(f"[Serial] No se pudo abrir {SERIAL_PORT}: {e}")
        print("[Serial] Modo sin hardware — iniciando demo si está activado")
        registrar_alerta("SISTEMA",
            f"ESP32 no conectado en {SERIAL_PORT} — modo monitor pasivo")

        if DEMO_MODE:
            hilo_demo()

# ============================================================
#  INICIO
# ============================================================

threading.Thread(target=leer_serial, daemon=True).start()

if __name__ == '__main__':
    print("=" * 60)
    print("  Airlock v3.1 — Sistema de Detección de Amenazas IoT")
    print(f"  Dashboard: http://127.0.0.1:5000")
    print(f"  ESP32:     {SERIAL_PORT} @ {BAUD_RATE} baud")
    print(f"  IA:        RandomForest (entrena automáticamente)")
    print(f"  Protocolo: JSON + HMAC-SHA256")
    print(f"  Demo Mode: {'ACTIVO' if DEMO_MODE else 'INACTIVO'}")
    print("=" * 60)
    app.run(host='127.0.0.1', port=5000, debug=False, threaded=True)