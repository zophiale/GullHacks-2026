"""Explicit live-capture entry point for packet classification."""

import argparse
import json

from scapy.all import sniff

from model import load_model, predict


def main() -> None:
    parser = argparse.ArgumentParser(description="Classify packets captured by Scapy.")
    parser.add_argument("--model", default="packet_model.pt")
    parser.add_argument("--count", type=int, default=10)
    parser.add_argument("--iface")
    args = parser.parse_args()
    model, metadata = load_model(args.model)

    packets = sniff(count=args.count, iface=args.iface, store=True)
    for packet in packets:
        print(json.dumps(predict(packet, model, metadata).__dict__, sort_keys=True))


if __name__ == "__main__":
    main()