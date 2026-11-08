from scapy.all import Packet, Raw, IP, TCP, sniff
import json
def _payload(packet: Packet) -> bytes:
    if Raw in packet:
        return bytes(packet[Raw].load)
    return b""


def extract_features(packet: Packet):
    """Extract a stable numeric feature vector from one Scapy packet."""
    payload = packet.json()
    payload_lower = payload.lower()
    packet_length = len(bytes(packet))
    ip = packet.getlayer(IP)
    protocol = ip.proto if ip is not None else 0
    # printable = sum(byte in b"\t\r\n" or 32 <= byte <= 126 for byte in payload)
    # controls = sum(byte < 32 and byte not in (9, 10, 13) for byte in payload)
    # suspicious = sum(byte in b"'\";|&$`<>\\\x00" for byte in payload)
    tcp = packet.getlayer(TCP)
    flags = str(tcp.flags) if tcp is not None else ""

    return payload

packet = sniff(count = 1)[0]

features = extract_features(packet)

features = json.loads(features)

# features['payload']['payload']['payload'] = features['payload']['payload']['payload'].decode()

print(features)