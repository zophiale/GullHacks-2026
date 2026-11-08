from flask import Flask
import scapy.all as scp

app = Flask(__name__)
benign = 0
malicious = 0

@app.route('/malice')
def log_malice():
    # report malicious packets
    global malicious
    malicious += 1

@app.route('/benign')
def log_benign():
    # conuter
    global benign
    benign += 1

@app.route('/reports')
def print_reports():
    # prints reported packets
    pass