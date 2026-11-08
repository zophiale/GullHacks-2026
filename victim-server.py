
from flask import Flask, request
from flask.cli import load_dotenv
from scapy.all import sniff

app = Flask(__name__)
benign = 0
malicious = 0
import psycopg2
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
    # sniff packets and report them
    def process_packet(packet):
        """
            Space for AI to use @model2.py functions to determine if packet is malicious or benign, and report to /malice or /benign endpoints
        """
    sniff(prn=process_packet, count=10)
    return "Sniffing complete."