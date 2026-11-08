
from flask import Flask, request
from flask.cli import load_dotenv
from scapy.packet import Packet

from model2 import ModelFilterer, load_config
from scapy.all import IP, Raw, TCP, UDP, sniff
import psycopg2
import json
import logging

app = Flask(__name__)
benign = 0
malicious = 0

# Global ModelFilterer instance for sniffer (loads default config)
FILTERER = ModelFilterer(config={"block_threshold": 0.7})

CONNECTION = "postgres://tsdbadmin:ypsrhc2nlbvlrf1v@t23b18pfz6.ouesmh1jty.tsdb.cloud.timescale.com:36213/tsdb?sslmode=require"
QUERY = "INSERT INTO logs (log_type, packet_dump) VALUES (%s, %s);"
# @app.route('/malice/<path:packet>')
# def log_malice(packet):
#     # report malicious packets
#     global malicious
#     malicious += 1
#     with psycopg2.connect(CONNECTION) as conn:
#         with conn.cursor() as cur:
#             cur.execute(QUERY, ("malicious", packet))

@app.route('/benign/<path:packet>')
def log_benign(packet):
    # counter for benign packets
    global benign
    benign += 1
    with psycopg2.connect(CONNECTION) as conn:
        with conn.cursor() as cur:
            cur.execute(QUERY, ("benign", packet))

@app.route('/reports/<path:packet>')
def print_reports(packet):
    # prints reported packets
    with psycopg2.connect(CONNECTION) as conn:
        with conn.cursor() as cur:
            cur.execute(QUERY, ("report", packet))

@app.route('/sniffer')
def sniffer():
    """Sniff packets, classify with ModelFilterer, report to endpoints."""

    def process_packet(packet: Packet):
        """Classify packet using ModelFilterer and forward to appropriate endpoint."""
        try:
            ip = packet.getlayer(IP)
            tcp = packet.getlayer(TCP)
            udp = packet.getlayer(UDP)
            transport = tcp or udp
            packet_data = {
                "src": ip.src if ip is not None else "127.0.0.1",
                "dst": ip.dst if ip is not None else "127.0.0.1",
                "sport": transport.sport if transport is not None else 0,
                "dport": transport.dport if transport is not None else 0,
                "flags": str(tcp.flags) if tcp is not None else "",
                "payload": bytes(packet[Raw].load) if Raw in packet else b"",
            }
            decision = FILTERER.evaluate(packet_data)

            # Build packet JSON for database storage
            packet_json = packet.json()

            # Forward to appropriate endpoint based on decision
            if decision.action == "BLOCK":
                with psycopg2.connect(CONNECTION) as conn:
                    with conn.cursor() as cur:
                        cur.execute(QUERY, ("report", packet_json))

                return json.dumps({
                    "action": decision.action,
                    "malicious": True,
                    "confidence": round(decision.confidence, 4),
                    "reason": decision.reason
                })
            else:
                with psycopg2.connect(CONNECTION) as conn:
                    with conn.cursor() as cur:
                        cur.execute(QUERY, ("benign", packet_json))

                return json.dumps({
                    "action": decision.action,
                    "malicious": False,
                    "confidence": round(decision.confidence, 4),
                    "reason": decision.reason
                })

        except Exception as e:
            print(f"Classification failed: {e}")
            # Default to benign on failure
            try:
                with psycopg2.connect(CONNECTION) as conn:
                    with conn.cursor() as cur:
                        log_type = "benign"
                        cur.execute(QUERY, (log_type, packet.json()))
            except Exception as e2:
                print(f"Could not log benign packet: {e2}")

            return json.dumps({
                "action": "UNKNOWN",
                "malicious": False,
                "error": str(e)
            })

    sniff(prn=process_packet, count=10)
    return "Sniffing complete."