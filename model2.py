# model2.py - Packet Filterer Module

"""
Packet-level maliciousness classifier with enforcement capabilities.
Extends model.py's predict interface with policy decisions.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional, Tuple

import numpy as np  # Type: ignore
import torch
from scapy.all import Packet

from model import (
    extract_features,
    load_model,
    predict,
)

# Configure audit logging
logging.basicConfig(
    level=logging.INFO,
    format='[FILTER] %(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Prediction:
    """Prediction result from model inference."""
    label: str
    confidence: float
    features: dict[str, float]


@dataclass
class Decision:
    """Enforcement decision result with policy metadata."""
    action: str  # "ALLOW" | "BLOCK"
    confidence: float
    reason: Optional[str]
    features: dict[str, float]
    threshold_met: bool
    
    def to_dict(self) -> dict:
        """Convert Decision to serializable dictionary."""
        return asdict(self)


class ModelFilterer:
    """Packet classifier with policy enforcement capability.
    
    Loads the trained model from model.py and enforces blocking decisions
    based on confidence thresholds for malicious packets.
    
    Example usage:
        filterer = ModelFilterer(config={"block_threshold": 0.7})
        decision = filterer.evaluate(packet_data)
        if decision.action == "BLOCK":
            # Log and enforce block on packet traffic
    
    Attributes:
        config: Configuration dictionary with thresholds and logging options
        model: Loaded PyTorch neural network for inference
        block_threshold: Probability threshold above which packets are blocked
    """
    
    def __init__(self, 
                 model_path: str = "packet_model.pt",
                 config: Optional[dict] = None):
        """Initialize filterer with trained model.
        
        Args:
            model_path: Path to .pt checkpoint file (default: packet_model.pt)
            config: Dictionary with block_threshold and logging options
            
        Raises:
            ValueError: If feature schema in checkpoint doesn't match expected format or
                      if model fails to load
        """
        if config is None:
            config = {"block_threshold": 0.5, "log_enabled": True}
        
        self.config = config
        self.block_threshold = config.get("block_threshold", 0.7)  # Updated from plan
        self.log_enabled = config.get("log_enabled", True)
        
        # Load trained model - same as model.py's load_model() at L214-222
        try:
            self.model, metadata = load_model(model_path)
        except (ValueError, FileNotFoundError, OSError, TypeError) as e:
            raise RuntimeError(f"Failed to load model from {model_path}: {e}") from e
        
        # Store metadata for feature normalization in evaluate()
        self.metadata = metadata
        
        # Use PACKET_NAMES tuple defined at module level (L224-245) as reference
        # This matches model.py's FEATURE_NAMES and ensures consistency across files
        self.feature_names = PACKET_NAMES
        
        logger.debug(f"Model loaded successfully. Features: {len(self.feature_names)}")

    
    def evaluate(self, packet_data: dict) -> Decision:
        """Evaluate packet against maliciousness policy and return enforcement decision.
        
        Extracts features from packet data, runs inference through the trained model,
        and returns a Decision object specifying ALLOW/BLOCK action based on confidence.
        
        Args:
            packet_data: Dict with packet fields needed for feature extraction (must match _packet_from_json structure)
            
        Returns:
            Decision object containing:
                - action: "ALLOW" or "BLOCK" based on policy and confidence
                - confidence: Normalized confidence in classification (0-1)
                - reason: Explanation for decision
                - features: Per-feature values used in inference
                - threshold_met: True if confidence >= block_threshold
            
        Raises:
            ValueError: If packet_data doesn't have required fields
        """
        # Extract features using same logic as model.py's extract_features() (L55-98)
        try:
            from scapy.all import IP, TCP, UDP, ICMP, DNS, Raw, Ether
            
            # Build a minimal valid Packet object for feature extraction
            packet = IP(src=packet_data.get("src", "127.0.0.1")) \
                     / TCP(sport=int(packet_data.get("sport", 54321)),
                          dport=int(packet_data.get("dport", 80)))
            
            # Add payload if provided
            if packet_data.get("payload"):
                packet = packet / Raw(load=packet_data["payload"])
            
            features = extract_features(packet)
        except Exception as e:
            logger.error(f"Failed to extract features: {e}")
            raise
        
        # Run model inference - same as model.py predict() at L230-231
        # Build feature matrix as list of lists (2D array format)
        values_list = [[features[name] for name in PACKET_NAMES]]
        normalized = np.asarray(values_list, dtype=np.float32)
        
        # Normalize features using training mean and scale - same as model.py L228
        if "mean" in self.metadata and "scale" in self.metadata:
            mean = np.asarray(self.metadata["mean"], dtype=np.float32)
            scale = np.asarray(self.metadata["scale"], dtype=np.float32)
            scale[scale == 0] = 1.0  # Avoid divide by zero
            normalized = (normalized - mean) / scale
        
        normalized_tensor = torch.from_numpy(normalized)
        prob = float(torch.sigmoid(self.model(normalized_tensor)).item())
        
        is_malicious = prob >= 0.5
        
        # Confidence calculation - same as model.py (L233): max(prob, 1-prob)
        decision_confidence = max(prob, 1.0 - prob)
        
        # Policy enforcement logic - BLOCK if malicious (prob >= 0.5) AND sufficient confidence
        action = "BLOCK" if is_malicious and decision_confidence >= self.block_threshold else "ALLOW"
        
        reason = None
        if is_malicious:
            if decision_confidence < self.block_threshold:
                reason = f"Confidence ({prob:.2%}) below threshold ({self.block_threshold}) - allowing uncertain traffic"
            else:
                reason = f"High confidence malicious detection ({prob:.2%}) - {decision_confidence:.0%} confidence after inverse normalization"
        else:
            reason = "Traffic classified as benign"
        
        # Prepare decision metadata (same structure as Decision dataclass in plan)
        threshold_met = prob >= self.block_threshold
        
        if self.log_enabled:
            logger.info(
                f"Packet processed - {action}: confidence {prob:.2%} (threshold: {self.block_threshold}) | "
                f"Inverse conf: {decision_confidence:.2%} | Reason: {reason}"
            )
        
        return Decision(
            action=action,
            confidence=decision_confidence,
            reason=reason,
            features=features,
            threshold_met=threshold_met
        )
    
    def batch_eval(self, packet_data_list: list[dict]) -> list[Decision]:
        """Evaluate multiple packets in parallel.
        
        Args:
            packet_data_list: List of packet dictionaries
            
        Returns:
            List of Decision objects (same order as input)
        """
        decisions = []
        for packet_data in packet_data_list:
            try:
                decision = self.evaluate(packet_data)
                decisions.append(decision)
            except Exception as e:
                logger.error(f"Failed to evaluate packet: {e}")
                raise
        return decisions


# Core feature definitions - MUST match model.py's FEATURE_NAMES (L18-39)
PACKET_NAMES = (
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

# Verify length - matches model.py's FEATURE_NAMES count (20 features total)
PACKET_NAMES_LENGTH = len(PACKET_NAMES)


def load_config(config_path: str = "filter_config.yaml") -> dict:
    """Load configuration from YAML file.
    
    Args:
        config_path: Path to YAML configuration file
        
    Returns:
        Parsed configuration dictionary (or defaults if file missing)
        
    Raises:
        FileNotFoundError: If config file doesn't exist and defaults not provided
    """
    import yaml
    
    # Default configuration values
    default_config = {
        "model": {"path": "packet_model.pt"},
        "thresholds": {"block_threshold": 0.7},
        "logging": {"enabled": True, "level": logging.INFO, "output": "filter_decisions.log"},
    }
    
    try:
        with open(config_path, "r") as f:
            loaded_config = yaml.safe_load(f)
        
        # Merge user config with defaults
        if loaded_config:
            return {**default_config, **loaded_config}
            
    except FileNotFoundError:
        logger.warning(f"Config file {config_path} not found - using defaults")
        return default_config
    except (yaml.YAMLError, OSError) as e:
        logger.error(f"Failed to parse {config_path}: {e}")
        raise


def log_audit_decision(decision: Decision) -> None:
    """Log decision to external audit log file.
    
    Args:
        decision: Decision object to log
    """
    # Simple console logging as primary output
    logger.info(
        f"AUDIT: {decision.action.upper()}"
        f"| Confidence:{decision.confidence:.2%}"
        f"| Reason:{decision.reason or 'N/A'}|"
        f"ThresholdMet:{decision.threshold_met}"
    )


if __name__ == "__main__":
    # Example test case demonstrating ModelFilterer usage
    
    # Create filterer with default config
    filterer = ModelFilterer()
    
    # Test packet 1 - obviously benign HTTP response
    benign_packet_data = {
        "src": "192.0.2.1",
        "dst": "198.51.100.1",
        "sport": 54321,
        "dport": 80,
        "flags": "PSH|ACK",
        "payload": b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
    }
    
    try:
        # Evaluate against policy
        benign_decision = filterer.evaluate(benign_packet_data)
        
        print(f"\n=== Benign Packet Evaluation Result ===")
        print(f"Action: {benign_decision.action}")
        print(f"Confidence: {benign_decision.confidence:.2%} (threshold: {filterer.block_threshold})")
        print(f"Reason: {benign_decision.reason}")
        print(f"Threshold Met: {benign_decision.threshold_met}")
        print(f"Features extracted: {PACKET_NAMES_LENGTH}")
    except Exception as e:
        logger.error(f"Benign packet evaluation failed: {e}")
        print(f"Error: {e}")
    
    # Test packet 2 - SQL injection attempt with shell command payload
    malicious_packet_data = {
        "src": "10.0.0.5",
        "dst": "198.51.100.1",
        "sport": 49152,
        "dport": 3389,  # RDP - sensitive service often targeted
        "flags": "ACK",
        "payload": b"\'OR SELECT * FROM users--\n/bin/sh -c id\r\n"
    }
    
    try:
        malicious_decision = filterer.evaluate(malicious_packet_data)
        
        print(f"\n=== Malicious Packet Evaluation Result ===")
        print(f"Action: {malicious_decision.action}")
        print(f"Confidence: {malicious_decision.confidence:.2%} (threshold: {filterer.block_threshold})")
        print(f"Reason: {malicious_decision.reason}")
        print(f"Threshold Met: {malicious_decision.threshold_met}")
        print(f"Features extracted: {PACKET_NAMES_LENGTH}")
    except Exception as e:
        logger.error(f"Malicious packet evaluation failed: {e}")
        print(f"Error: {e}")
        
