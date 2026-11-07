import tempfile
import unittest
from pathlib import Path

from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

from model import (
    FEATURE_NAMES,
    extract_features,
    generate_starter_data,
    load_model,
    predict,
    save_model,
    train,
)


class PacketModelTests(unittest.TestCase):
    def test_feature_schema_is_stable(self):
        packet = IP(ttl=64) / TCP(sport=1234, dport=80, flags="PA") / Raw(load=b"GET / HTTP/1.1\r\n")
        features = extract_features(packet)
        self.assertEqual(tuple(features), FEATURE_NAMES)
        self.assertEqual(features["contains_http_method"], 1.0)

    def test_starter_data_trains_and_round_trips(self):
        rows, labels = generate_starter_data(samples_per_class=16)
        model, metadata = train(rows, labels, epochs=20)
        packet = IP() / TCP(dport=80, flags="S") / Raw(load=b"admin' OR '1'='1'--")
        result = predict(packet, model, metadata)
        self.assertIn(result.label, {"benign", "malicious"})
        self.assertGreaterEqual(result.confidence, 0.5)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "model.pt"
            save_model(model, metadata, path)
            loaded, loaded_metadata = load_model(path)
            self.assertEqual(predict(packet, loaded, loaded_metadata).label, result.label)


if __name__ == "__main__":
    unittest.main()
