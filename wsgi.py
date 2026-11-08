from flask import Flask, redirect, url_for, abort
import scapy.all as scp
import psycopg2

conn = psycopg2.connect(databse = 'logs')
cur = conn.cursor()

app = Flask(__name__)
benign = 0
malicious = 0

@app.route('/malice')
def log_malice():
    # report malicious packets
    print('malice')
    global malicious, cur
    malicious += 1
    return redirect(url_for('idle'))

@app.route('/benign')
def log_benign():
    # conuter
    global benign, cur
    benign += 1
    return redirect(url_for('idle'))

@app.route('/reports')
def print_reports():
    # prints reported packets
    return redirect(url_for('idle'))

@app.route('/')
def idle():
    return redirect(url_for('log_malice'))