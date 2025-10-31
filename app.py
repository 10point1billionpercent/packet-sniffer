# app.py (fix: tamper applies independently of sniff)
import threading
import socket
import time
import binascii
import random
import hashlib
import os
import string
from flask import Flask, request, jsonify, send_from_directory

# CONFIG - hosts & ports
SNIFFER_HOST, SNIFFER_PORT = "127.0.0.1", 5005
HOST1_HOST, HOST1_PORT = "127.0.0.1", 6006
HOST2_HOST, HOST2_PORT = "127.0.0.1", 6005
FLASK_PORT = 8000
STATIC_INDEX = "index.html"

# Shared state (defaults: sniff & tamper OFF)
sniff_enabled = False
tamper_enabled = False
tamper_cfg = {"find": "secret", "replace": "[HACKED]"}
captured = []   # list of logged packet dicts
seq = 0

app = Flask(__name__, static_folder='.')

# ---- helpers ----
def md5_checksum(b: bytes) -> str:
    return hashlib.md5(b).hexdigest()

def make_packet(src, dst, sport, dport, proto, payload, seqno, sent_ck=None):
    pb = payload.encode()
    full_ck = sent_ck if sent_ck is not None else md5_checksum(pb)
    return {
        "seq": seqno,
        "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
        "src": src,
        "dst": dst,
        "sport": sport,
        "dport": dport,
        "proto": proto,
        "len": len(pb),
        "payload_ascii": payload,
        "payload_hex": binascii.hexlify(pb).decode(),
        "checksum_full": full_ck,
        "checksum_short": full_ck[:8],
        "tampered": False
    }

def tamper_packet_payload_only(pkt):
    """
    Deterministic destructive tamper:
      - Always replace the payload with random printable garbage (length similar to original).
    IMPORTANT: we DO NOT change pkt['checksum_full'] here so receiver detects INVALID.
    """
    s = pkt["payload_ascii"] or ""
    # produce random printable garbage of similar length (at least 4 chars)
    orig_len = max(4, len(s))
    # vary length slightly for realism
    new_len = max(1, int(orig_len * 0.9))  # keep roughly same size
    charset = string.ascii_letters + string.digits + string.punctuation
    s2 = ''.join(random.choice(charset) for _ in range(new_len))

    if s2 != s:
        pkt["payload_ascii"] = s2
        pkt["payload_hex"] = binascii.hexlify(s2.encode()).decode()
        pkt["len"] = len(s2.encode())
        # KEEP original checksum (do NOT recalc)
        pkt["tampered"] = True
    return pkt

# ---- receiver templates (host1 & host2 identical behavior) ----
def handle_receiver_conn(data_bytes):
    try:
        txt = data_bytes.decode()
    except:
        txt = data_bytes.decode(errors='replace')

    sent_ck = None
    payload = txt
    # header parsing: support "TO:...\nCHECKSUM:...\n<payload>" or "CHECKSUM:...\n<payload>"
    if txt.startswith("TO:"):
        parts = txt.split("\n", 2)
        if len(parts) >= 2 and parts[1].startswith("CHECKSUM:"):
            sent_ck = parts[1].split(":",1)[1].strip()
            payload = parts[2] if len(parts) > 2 else ""
        else:
            payload = "\n".join(parts[1:])
    elif txt.startswith("CHECKSUM:"):
        head, rest = txt.split("\n",1) if "\n" in txt else (txt, "")
        sent_ck = head.split(":",1)[1].strip() if ":" in head else None
        payload = rest

    computed = md5_checksum(payload.encode())
    validity = "VALID" if (sent_ck is not None and computed == sent_ck) else "INVALID"
    # reply includes computed checksum for the client UI
    return f"ACK: validity={validity} recv_checksum={computed}".encode()

def host_server(bind_host, bind_port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((bind_host, bind_port))
    s.listen(5)
    print(f"[host] listening on {bind_host}:{bind_port}")
    while True:
        conn, addr = s.accept()
        with conn:
            data = conn.recv(8192)
            if not data:
                continue
            resp = handle_receiver_conn(data)
            try:
                conn.sendall(resp)
            except:
                pass

# ---- Sniffer / proxy ----
def sniffer_server():
    global sniff_enabled, captured, seq, tamper_enabled, tamper_cfg
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((SNIFFER_HOST, SNIFFER_PORT))
    s.listen(5)
    print(f"[sniffer] listening on {SNIFFER_HOST}:{SNIFFER_PORT} -> forwarding between hosts")
    while True:
        conn, addr = s.accept()
        with conn:
            data = conn.recv(8192)
            if not data:
                continue
            try:
                txt = data.decode()
            except:
                txt = data.decode(errors='replace')

            # parse headers
            to_target = None
            sent_ck = None
            payload = txt
            if txt.startswith("TO:"):
                parts = txt.split("\n", 2)
                to_target = parts[0].split(":",1)[1].strip() if ":" in parts[0] else None
                if len(parts) > 1 and parts[1].startswith("CHECKSUM:"):
                    sent_ck = parts[1].split(":",1)[1].strip()
                    payload = parts[2] if len(parts) > 2 else ""
                else:
                    payload = parts[1] if len(parts) > 1 else ""
            elif txt.startswith("CHECKSUM:"):
                head, rest = txt.split("\n",1) if "\n" in txt else (txt, "")
                sent_ck = head.split(":",1)[1].strip() if ":" in head else None
                payload = rest
                to_target = "HOST2"
            else:
                payload = txt
                sent_ck = md5_checksum(payload.encode())
                to_target = "HOST2"

            # build packet record using ORIGINAL checksum (sent_ck)
            seq += 1
            src_str = f"{addr[0]}:{addr[1]}"
            dst_port = HOST1_PORT if to_target == "HOST1" else HOST2_PORT
            dst_str = f"{HOST1_HOST}:{HOST1_PORT}" if to_target == "HOST1" else f"{HOST2_HOST}:{HOST2_PORT}"

            pkt = make_packet(src=src_str, dst=dst_str, sport=0,
                              dport=dst_port, proto="SIMSIM", payload=payload, seqno=seq, sent_ck=sent_ck)

            # Apply tamper ALWAYS if enabled (independent of sniff)
            if tamper_enabled:
                pkt = tamper_packet_payload_only(pkt)

            # prepare payload_preview for logs (always available from pkt after possible tamper)
            payload_preview = pkt["payload_ascii"][:60] + ("..." if len(pkt["payload_ascii"]) > 60 else "")

            # log only if sniff enabled (sniff controls visibility only)
            if sniff_enabled:
                log_entry = {
                    "seq": pkt["seq"],
                    "ts": pkt["ts"],
                    "src": pkt["src"],
                    "dst": pkt["dst"],
                    "checksum_full": pkt["checksum_full"],
                    "checksum_short": pkt["checksum_short"],
                    "tampered": pkt["tampered"],
                    "payload_preview": payload_preview
                }
                captured.append(log_entry)

            # simulate transit delay and forward
            delay_seconds = random.uniform(1.0, 3.0)
            try:
                time.sleep(delay_seconds)
                target = (HOST1_HOST, HOST1_PORT) if to_target == "HOST1" else (HOST2_HOST, HOST2_PORT)
                s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s2.connect(target)
                # forward ORIGINAL checksum header and (possibly tampered) payload
                forward_msg = f"CHECKSUM:{pkt['checksum_full']}\n{pkt['payload_ascii']}".encode()
                s2.sendall(forward_msg)
                resp = s2.recv(4096)
                s2.close()
            except Exception as e:
                resp = f"ERR forwarding: {e}".encode()

            # reply to origin with sniffer ack + delay (minimal)
            try:
                resp_text = resp.decode(errors='replace')
            except:
                resp_text = str(resp)
            try:
                conn.sendall(f"RELAY_ACK:{resp_text}||DELAY:{delay_seconds}".encode())
            except:
                pass

# ---- Flask endpoints ----
@app.route('/')
def index():
    if not os.path.exists(STATIC_INDEX):
        return f"index.html not found. place {STATIC_INDEX} in same folder", 404
    return send_from_directory('.', STATIC_INDEX)

@app.route('/state', methods=['GET'])
def state():
    # return boolean states for frontend initialization
    return jsonify({"sniff": sniff_enabled, "tamper": tamper_enabled, "tamper_cfg": tamper_cfg})

@app.route('/preview', methods=['POST'])
def preview():
    data = request.get_json() or {}
    msg = data.get('msg','')
    ck = md5_checksum(msg.encode())
    pretty = (
        f"--- Packet Preview (Sender) ---\n"
        f"ts: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"src: Sender\n"
        f"dst: Receiver (via Sniffer)\n"
        f"proto: SIMTCP\n"
        f"len: {len(msg.encode())}\n"
        f"checksum (md5): {ck}\n"
        f"payload (ascii):\n{msg}\n"
    )
    return jsonify({"pretty": pretty, "pretty_ck": ck})

@app.route('/send', methods=['POST'])
def send():
    """
    Expects JSON: { "msg": "...", "sender": 1 or 2 }
    """
    global seq, captured, sniff_enabled, tamper_enabled
    data = request.get_json() or {}
    msg = data.get('msg','')
    sender = int(data.get('sender', 1))
    sent_ck = md5_checksum(msg.encode())

    target = "HOST2" if sender == 1 else "HOST1"
    packed = f"TO:{target}\nCHECKSUM:{sent_ck}\n{msg}".encode()

    try:
        c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        c.connect((SNIFFER_HOST, SNIFFER_PORT))
        c.sendall(packed)
        raw = c.recv(8192).decode(errors='replace')
        c.close()
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    # parse sniffer response to extract receiver ack and delay
    ack = "no ack"
    delay = 0.0
    recv_ck = None
    if raw.startswith("RELAY_ACK:"):
        try:
            parts = raw.split("||")
            ack_full = parts[0].split("RELAY_ACK:",1)[1]
            delay_part = parts[1]
            delay = float(delay_part.split("DELAY:",1)[1])
            if "recv_checksum=" in ack_full:
                recv_ck = ack_full.split("recv_checksum=",1)[1].strip()
            if "VALID" in ack_full and "INVALID" not in ack_full:
                ack = "VALID"
            elif "INVALID" in ack_full:
                ack = "INVALID"
            else:
                ack = ack_full
        except Exception:
            ack = raw

    # prepare pretty_post only if sniff ON (keeps packetPretty clean when sniff OFF)
    pretty_post = ""
    logs_to_send = []
    if sniff_enabled:
        pretty_post = (
            f"--- Packet After Sniffer (forwarded) ---\n"
            f"ts: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"src: Sniffer\n"
            f"dst: {'Host2' if target=='HOST2' else 'Host1'}\n"
            f"len: {len(msg.encode())}\n"
            f"sent_checksum (orig short): {sent_ck[:8]}\n"
            f"ack_from_receiver: {ack}\n"
        )
        if captured:
            last = captured[-1]
            # human friendly single-line log (no dict dump)
            line = f"Log: seq={last['seq']} time={last['ts'].split(' ')[1]} src={last['src'].split(':')[0]} dst={last['dst'].split(':')[0]} tampered={'Yes' if last['tampered'] else 'No'} chk={last['checksum_short']}"
            pretty_post += "\n--- Sniffer Log (most recent) ---\n" + line + "\n"

        # include full trimmed logs (with payload_preview) for the UI table & received payload
        for e in captured:
            logs_to_send.append({
                "seq": e.get("seq"),
                "ts": e.get("ts"),
                "src": e.get("src"),
                "dst": e.get("dst"),
                "checksum_full": e.get("checksum_full"),
                "checksum_short": e.get("checksum_short"),
                "tampered": e.get("tampered"),
                "payload_preview": e.get("payload_preview")
            })
    else:
        # sniff is off: intentionally send no pretty_post and empty logs
        pretty_post = ""
        logs_to_send = []

    return jsonify({
        "ack": ack,
        "recv_checksum": recv_ck,
        "delay": delay,
        "pretty_post": pretty_post,
        "logs": logs_to_send
    })

@app.route('/toggle_sniff', methods=['POST'])
def toggle_sniff():
    global sniff_enabled, captured
    sniff_enabled = not sniff_enabled
    return jsonify({"sniff": sniff_enabled})

@app.route('/toggle_tamper', methods=['POST'])
def toggle_tamper():
    global tamper_enabled
    tamper_enabled = not tamper_enabled
    return jsonify({"tamper": tamper_enabled})

@app.route('/set_tamper', methods=['POST'])
def set_tamper():
    global tamper_cfg
    data = request.get_json() or {}
    f = data.get('find')
    r = data.get('replace')
    if f is not None and f != "":
        tamper_cfg['find'] = f
    if r is not None and r != "":
        tamper_cfg['replace'] = r
    return ('', 204)

@app.route('/logs', methods=['GET'])
def logs():
    out = []
    for e in captured:
        out.append({
            "seq": e.get("seq"),
            "ts": e.get("ts"),
            "src": e.get("src"),
            "dst": e.get("dst"),
            "checksum_full": e.get("checksum_full"),
            "checksum_short": e.get("checksum_short"),
            "tampered": e.get("tampered"),
            "payload_preview": e.get("payload_preview")
        })
    return jsonify(out)

@app.route('/clear_logs', methods=['POST'])
def clear_logs():
    global captured
    captured = []
    return ('', 204)

# ---- start servers ----
if __name__ == "__main__":
    t1 = threading.Thread(target=host_server, args=(HOST1_HOST, HOST1_PORT), daemon=True)
    t2 = threading.Thread(target=host_server, args=(HOST2_HOST, HOST2_PORT), daemon=True)
    ts = threading.Thread(target=sniffer_server, daemon=True)
    t1.start(); t2.start(); ts.start()
    print(f"Open http://127.0.0.1:{FLASK_PORT} (ensure {STATIC_INDEX} is in same folder)")
    app.run(port=FLASK_PORT, debug=False)
