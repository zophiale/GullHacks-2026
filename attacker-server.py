import random
import requests
from scapy.all import Packet

malicious = []
benign = []

r = random.randint(0, 1)
if r == 1:
    requests.post(random.choice(malicious))
else:
    requests.post(random.choice(benign))