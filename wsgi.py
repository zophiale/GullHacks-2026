from flask import Flask

app = Flask(__name__)

@app.route('/malice')
def log_malicious():
    pass

@app.route('/benign')
def log_benign():
    pass

@app.route('/reports')
def log_all():
    pass