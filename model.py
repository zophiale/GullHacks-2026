"""Packet-level maliciousness classifier built on Scapy and PyTorch."""

from __future__ import annotations

import argparse
import csv
import json
import random
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Sequence

import numpy as np
import torch
from scapy.all import IP, Raw, TCP, UDP, Packet, rdpcap


FEATURE_NAMES = (
    "packet_length",
    "ip_version",
    "ttl",
    "protocol_tcp",
    "protocol_udp",
    "protocol_icmp",
    "protocol_other",
    "source_port",
    "destination_port",
    "tcp_syn",
    "tcp_ack",
    "tcp_fin",
    "tcp_rst",
    "payload_length",
    "payload_printable_ratio",
    "payload_control_ratio",
    "suspicious_byte_ratio",
    "contains_http_method",
    "contains_sql_marker",
    "contains_shell_marker",
)


@dataclass(frozen=True)
class Prediction:
    label: str
    confidence: float
    features: dict[str, float]


def _payload(packet: Packet) -> bytes:
    if Raw in packet:
        return bytes(packet[Raw].load)
    return b""


def extract_features(packet: Packet) -> dict[str, float]:
    """Extract a stable numeric feature vector from one Scapy packet."""
    payload = _payload(packet)
    payload_lower = payload.lower()
    packet_length = len(bytes(packet))
    ip = packet.getlayer(IP)
    protocol = ip.proto if ip is not None else 0
    printable = sum(byte in b"\t\r\n" or 32 <= byte <= 126 for byte in payload)
    controls = sum(byte < 32 and byte not in (9, 10, 13) for byte in payload)
    suspicious = sum(byte in b"'\";|&$`<>\\\x00" for byte in payload)
    tcp = packet.getlayer(TCP)
    flags = str(tcp.flags) if tcp is not None else ""

    values = {
        "packet_length": float(packet_length),
        "ip_version": float(ip.version) if ip is not None else 0.0,
        "ttl": float(ip.ttl) if ip is not None else 0.0,
        "protocol_tcp": float(protocol == 6),
        "protocol_udp": float(protocol == 17),
        "protocol_icmp": float(protocol == 1),
        "protocol_other": float(protocol not in (1, 6, 17)),
        "source_port": float(tcp.sport if tcp is not None else (packet[UDP].sport if UDP in packet else 0)),
        "destination_port": float(
            tcp.dport if tcp is not None else (packet[UDP].dport if UDP in packet else 0)
        ),
        "tcp_syn": float("S" in flags),
        "tcp_ack": float("A" in flags),
        "tcp_fin": float("F" in flags),
        "tcp_rst": float("R" in flags),
        "payload_length": float(len(payload)),
        "payload_printable_ratio": printable / len(payload) if payload else 0.0,
        "payload_control_ratio": controls / len(payload) if payload else 0.0,
        "suspicious_byte_ratio": suspicious / len(payload) if payload else 0.0,
        "contains_http_method": float(
            any(payload_lower.startswith(method) for method in (b"get ", b"post ", b"put ", b"delete "))
        ),
        "contains_sql_marker": float(
            any(marker in payload_lower for marker in (b" or ", b"union select", b"select ", b"--"))
        ),
        "contains_shell_marker": float(
            any(marker in payload_lower for marker in (b"/bin/sh", b"cmd.exe", b"wget ", b"curl "))
        ),
    }
    return {name: values[name] for name in FEATURE_NAMES}


class PacketMLP(torch.nn.Module):
    def __init__(self, input_size: int = len(FEATURE_NAMES)) -> None:
        super().__init__()
        self.network = torch.nn.Sequential(
            torch.nn.Linear(input_size, 32),
            torch.nn.ReLU(),
            torch.nn.Linear(32, 16),
            torch.nn.ReLU(),
            torch.nn.Linear(16, 1),
        )

    def forward(self, inputs: torch.Tensor) -> torch.Tensor:
        return self.network(inputs).squeeze(-1)


def _set_seed(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)


def _feature_matrix(rows: Sequence[dict[str, float]]) -> np.ndarray:
    return np.asarray([[row[name] for name in FEATURE_NAMES] for row in rows], dtype=np.float32)


def generate_starter_data(seed: int = 7, samples_per_class: int = 64) -> tuple[list[dict[str, float]], list[int]]:
    """Generate deterministic labeled packet features for smoke tests and demos."""
    rng = random.Random(seed)
    rows: list[dict[str, float]] = []
    labels: list[int] = []
    for label in (0, 1):
        for _ in range(samples_per_class):
            payload_length = rng.randint(8, 80) if label == 0 else rng.randint(40, 180)
            row = {name: 0.0 for name in FEATURE_NAMES}
            row.update(
                packet_length=float(payload_length + rng.randint(40, 70)),
                ip_version=4.0,
                ttl=float(rng.choice((32, 64, 128))),
                protocol_tcp=1.0,
                protocol_other=0.0,
                source_port=float(rng.randint(1024, 65535)),
                destination_port=float(rng.choice((80, 443, 8080))),
                tcp_ack=1.0,
                payload_length=float(payload_length),
                payload_printable_ratio=rng.uniform(0.7, 1.0),
            )
            if label:
                row.update(
                    destination_port=80.0,
                    tcp_syn=1.0,
                    suspicious_byte_ratio=rng.uniform(0.08, 0.35),
                    contains_sql_marker=float(rng.random() > 0.35),
                    contains_shell_marker=float(rng.random() > 0.65),
                )
            rows.append(row)
            labels.append(label)
    return rows, labels


def write_feature_csv(path: str | Path, rows: Sequence[dict[str, float]], labels: Sequence[int]) -> None:
    with Path(path).open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=[*FEATURE_NAMES, "label"])
        writer.writeheader()
        for row, label in zip(rows, labels):
            writer.writerow({**row, "label": label})


def read_feature_csv(path: str | Path) -> tuple[list[dict[str, float]], list[int]]:
    with Path(path).open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        missing = set(FEATURE_NAMES) - set(reader.fieldnames or ())
        if missing or "label" not in (reader.fieldnames or ()):
            raise ValueError(f"CSV is missing required columns: {sorted(missing | {'label'})}")
        rows, labels = [], []
        for record in reader:
            rows.append({name: float(record[name]) for name in FEATURE_NAMES})
            labels.append(int(record["label"]))
    if not rows or set(labels) != {0, 1}:
        raise ValueError("CSV must contain both benign (0) and malicious (1) rows")
    return rows, labels


def train(
    rows: Sequence[dict[str, float]],
    labels: Sequence[int],
    *,
    epochs: int = 120,
    seed: int = 7,
) -> tuple[PacketMLP, dict[str, np.ndarray | list[str] | int | float]]:
    if len(rows) != len(labels) or len(rows) < 4 or set(labels) != {0, 1}:
        raise ValueError("Training data must have matching rows and both binary classes")
    _set_seed(seed)
    matrix = _feature_matrix(rows)
    mean = matrix.mean(axis=0)
    scale = matrix.std(axis=0)
    scale[scale == 0] = 1.0
    inputs = torch.from_numpy((matrix - mean) / scale)
    targets = torch.tensor(labels, dtype=torch.float32)
    model = PacketMLP()
    optimizer = torch.optim.Adam(model.parameters(), lr=0.01)
    loss_fn = torch.nn.BCEWithLogitsLoss()
    model.train()
    for _ in range(epochs):
        optimizer.zero_grad()
        loss_fn(model(inputs), targets).backward()
        optimizer.step()
    return model, {"feature_names": list(FEATURE_NAMES), "mean": mean, "scale": scale, "seed": seed}


def save_model(model: PacketMLP, metadata: dict, path: str | Path) -> None:
    torch.save({"state_dict": model.state_dict(), "metadata": metadata}, path)


def load_model(path: str | Path) -> tuple[PacketMLP, dict]:
    checkpoint = torch.load(path, map_location="cpu", weights_only=False)
    metadata = checkpoint["metadata"]
    if tuple(metadata["feature_names"]) != FEATURE_NAMES:
        raise ValueError("Model feature schema does not match this code version")
    model = PacketMLP()
    model.load_state_dict(checkpoint["state_dict"])
    model.eval()
    return model, metadata


def predict(packet: Packet, model: PacketMLP, metadata: dict) -> Prediction:
    features = extract_features(packet)
    values = np.asarray([[features[name] for name in FEATURE_NAMES]], dtype=np.float32)
    normalized = (values - metadata["mean"]) / metadata["scale"]
    with torch.no_grad():
        probability = float(torch.sigmoid(model(torch.from_numpy(normalized))).item())
    return Prediction(
        label="malicious" if probability >= 0.5 else "benign",
        confidence=probability if probability >= 0.5 else 1.0 - probability,
        features=features,
    )


def _packet_from_json(record: dict) -> Packet:
    payload = record.get("payload", "").encode("utf-8")
    packet = IP(src=record.get("src", "192.0.2.1"), dst=record.get("dst", "198.51.100.1")) / TCP(
        sport=int(record.get("sport", 12345)), dport=int(record.get("dport", 80)), flags=record.get("flags", "A")
    )
    return packet / Raw(load=payload) if payload else packet


def main() -> None:
    parser = argparse.ArgumentParser(description="Train or run the Scapy packet classifier.")
    parser.add_argument("--model", default="packet_model.pt")
    parser.add_argument("--train-csv")
    parser.add_argument("--starter-data", action="store_true")
    parser.add_argument("--pcap")
    parser.add_argument("--packet-json")
    args = parser.parse_args()
    model_path = Path(args.model)
    if args.starter_data or args.train_csv:
        rows, labels = generate_starter_data() if args.starter_data else read_feature_csv(args.train_csv)
        model, metadata = train(rows, labels)
        save_model(model, metadata, model_path)
        print(f"saved model to {model_path}")
        return
    model, metadata = load_model(model_path)
    packets: Iterable[Packet]
    if args.pcap:
        packets = rdpcap(args.pcap)
    elif args.packet_json:
        packets = [_packet_from_json(json.loads(Path(args.packet_json).read_text(encoding="utf-8")))]
    else:
        raise SystemExit("provide --starter-data/--train-csv for training or --pcap/--packet-json for inference")
    for packet in packets:
        result = predict(packet, model, metadata)
        print(json.dumps(asdict(result), sort_keys=True))


if __name__ == "__main__":
    main()