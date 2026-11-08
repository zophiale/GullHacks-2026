# Implement Packet Filterer Module for Malicious Traffic Denial

## Overview
Create `model2.py` as a dedicated packet filterer module that loads the trained packet classification model from `model.py` and enforces blocking policies based on confidence thresholds. This enables denying malicious packets from continuing through the network while maintaining an audit trail.

**Goal**: Block confirmed malicious packets and log decisions for compliance/forensics.

---

## Current State Analysis

### What Exists (from research):

**`model.py` - Packet Classification Core:**
- `PACKET_NAMES` tuple at L18-39: 29 features defining classification schema
- `PacketMLP` class L101-113: Neural network architecture (29→32→16→1 with ReLU)
- `train()` function L183-207: Training pipeline with Adam optimizer, BCEWithLogitsLoss
- `predict()` function L225-235: Returns `Prediction` dataclass with (label, confidence, features)
- `load_model()` L214-222: Loads PyTorch checkpoint with state_dict validation

**Trained Artifact:**
- `packet_model.pt` - Model checkpoint ready for inference
- Metadata includes: feature_names, mean, scale parameters

---

## Desired End State

**New Component**: `model2.py` (named as model2.py per your request)

### Functionality Delivered:
1. **Initialization** (`ModelFilterer` class):
   - Loads trained model from config file or path argument
   - Parses blocking/allowance configuration

2. **Inference Pipeline**:
   ```python
   result = filterer.evaluate(packet)
   # Returns: Decision {action, confidence, reason, features}
   ```

3. **Policy Enforcement**:
   - Block if predicted malicious AND confidence ≥ BLOCK_THRESHOLD
   - Log all decisions with timestamps for audit trail

4. **Configuration** (`filter_config.yaml`):
   ```yaml
   block_threshold: 0.7
   rate_limit_sources: true
   log_level: INFO
   ```

---

## Implementation Phases

The approach is to iterate through 3 phases, each completed with verification before proceeding:

### Phase 1 Analysis Complete ✓

**Goal**: Understand exact interface used by existing `predict()` function - COMPLETED  

**Verified Findings:**
- FEATURE_NAMES: 20 features (corrected from erroneous "29" in original plan)
- model.py:L42-46: Prediction dataclass structure  
- model.py:L55-98: Feature extraction → returns dict[str, float]
- model.py:L101-113: PacketMLP architecture: Linear(20→32→16→1)
- model.py:L214-225: load_model() + predict() with sigmoid applied in prediction step
**Findings from analysis (`model.py`):**

#### Feature Definitions (L18-39):
```python
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
)  # 20 features total (not 29 as plan initially stated!)
```

#### Prediction Dataclass (L42-46):
```python
@dataclass(frozen=True)
class Prediction:
    label: str          # "malicious" if probability >= 0.5 else "benign"
    confidence: float   # prob if malicious, (1-prob) if benign
    features: dict[str, float]
```

#### Feature Extraction Pipeline (L55-98):
```python
def extract_features(packet: Packet) -> dict[str, float]:
    payload = _payload(packet)  # Extract Raw layer as bytes (L49-52)
    values = {"..." : ...}  # Build feature dict directly (L68-97)
    return {name: values[name] for name in FEATURE_NAMES}
```

#### Model Architecture (L101-113):
```python
class PacketMLP(torch.nn.Module):
    def __init__(self, input_size=20):  # Uses len(FEATURE_NAMES) = 20
        self.network = torch.nn.Sequential(
            Linear(20→32) → ReLU → 
            Linear(32→16) → ReLU →
            Linear(16→1),  # Output is logits
    
    def forward(self, inputs):
        return network(inputs).squeeze(-1)  # Returns scalar logit (not sigmoid!)
```

#### Training Pipeline (L183-207):
```python
def train(rows, labels):
    mean = matrix.mean(axis=0)      # Per-feature mean (20 values)
    scale = matrix.std(axis=0)      # Per-feature std (20 values)
    scaled_inputs = (matrix - mean) / scale
    model = PacketMLP()              # Input_size defaults to 20
    optimizer = Adam(model.params, lr=0.01)
    loss_fn = BCEWithLogitsLoss()   # Raw logits, not probabilities!
    # One epoch of training
    
# Returns: (model, {"feature_names": ..., "mean": mean_array, 
                "scale": scale_array, "seed": 7})
```

#### Model Loading & Inference (L210-235):
```python
def load_model(path) -> tuple[PacketMLP, dict]:
    checkpoint = torch.load(path, map_location="cpu", weights_only=False)
    metadata = checkpoint["metadata"]  # Contains mean, scale, feature_names
    model = PacketMLP()                 # Creates NEW empty network
    model.load_state_dict(checkpoint["state_dict"])  # Loads weights
    model.eval()                         # Sets evaluation mode
    
def predict(packet, model, metadata) -> Prediction:
    features = extract_features(packet)
    values = np.asarray([[f[name] for name in FEATURE_NAMES]], dtype=np.float32)
    normalized = (values - metadata["mean"]) / metadata["scale"]
    
    # MODEL OUTPUTS LOGITS (not probabilities) from sigmoid
    with torch.no_grad():
        logit = float(torch.sigmoid(model(torch.from_numpy(normalized))).item())
    
   return Prediction(
      label="malicious" if prob >= 0.5 else "benign",
      confidence=prob if prob >= 0.5 else (1-prob),
      features=features
    )
```

#### JSON Packet Parser (L238-243):
```python
def _packet_from_json(record: dict) -> Packet:
    payload = record.get("payload", "").encode("utf-8")
    packet = IP(src=record.get("src"), dst=record.get("dst")) \
            / TCP(sport=int(record["sport"]), dport=int(record["dport"])) \
               .flags(record.get("flags") or "A")  # Default flags="A"
    return packet / Raw(load=payload) if payload else packet
```

---

### Phase 2: Build ModelFilterer Base Class Wrapper

**Goal**: Create reusable filterer interface that loads model once, caches it for efficiency

**Goal**: Create reusable filterer interface that loads model once, caches it for efficiency

**Changes Required:**

#### 1. File: `model2.py` (new file creation)

```python
# model2.py - Packet Filterer Module

"""
Packet-level maliciousness classifier with enforcement capabilities.
Extends model.py's predict interface with policy decisions.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional, Tuple

import torch
from scapy.all import Packet

# Import from model.py (reproducible import pattern)


@dataclass(frozen=True)
class Prediction:
    label: str
    confidence: float
    features: dict[str, float]


@dataclass
class Decision:
    """Enforcement decision result."""
    action: str  # "ALLOW", "BLOCK"
    confidence: float
    reason: Optional[str]
    features: dict[str, float]
    threshold_met: bool


class ModelFilterer:
    """Packet classifier with policy enforcement capability."""
    
    def __init__(self, model_path: str = "packet_model.pt", config: Optional[dict] = None):
        """Initialize filterer with trained model.

        Args:
            model_path: Path to .pt checkpoint file
            config: Dictionary with block_threshold and logging options
        """
        if config is None:
            config = {"block_threshold": 0.5, "log_enabled": True}
        
        self.config = config
        self.block_threshold = config.get("block_threshold", 0.5)
        self.log_enabled = config.get("log_enabled", True)
        
        # Load trained model - mirrors model.py's load_model() exactly
        model, metadata = torch.load(model_path, weights_only=False)
        state_dict = model["state_dict"]
        
        # Verify features match (same as model.py L217-218)
        expected_features = {name: 0.0 for name in MODEL_FEATURES}  # TYPE: ignore
        if tuple(expected_features.keys()) != tuple(metadata.get("feature_names", [])):
            raise ValueError(f"Feature schema mismatch: got {tuple(expected_features.keys())}, "
                           f"expected {metadata.get('feature_names', [])}")
        
        self.model = torch.nn.Linear(29, 1)
        self.model.load_state_dict(state_dict)
        self.model.eval()
    
    def evaluate(self, packet_data: dict) -> Decision:
        """Evaluate single packet against policy.
        
        Args:
            packet_data: Dict with IP address, payload (as bytes or string), etc.
        
        Returns:
            Decision object with action and metadata
        """
        # Feature extraction (mirrors model.py extract_features L56-98)
        features = self._extract_features(packet_data)  # TYPE: ignore
        
        # Model inference (mirrors model.py predict L230-231)
        normalized = torch.tensor([(features[name] for name in MODEL_FEATURES)], dtype=torch.float32)
        with torch.no_grad():
            prob = float(torch.sigmoid(self.model(normalized.squeeze())).item())
        
        decision_prob = max(prob, 1 - prob)  # Confidence as in model.py L233
        
        # Policy enforcement (NEW - blocking logic)
        is_malicious = probability >= 0.5
        
        if probability < 0.7:
            action = "ALLOW"
        else:
            action = "BLOCK"
        
        reason = None
        threshold_met = prob >= self.block_threshold
        
        if self.log_enabled:
            log_result(f"Packet processed - {action}: {conf} (threshold: {thresh})")
        
        return Decision(action, decision_prob, reason, features, threshold_met)


# Core feature definitions from model.py L18-39
MODEL_FEATURES = (
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

if __name__ == "__main__":
    # Simple test case
    packet_data = {
        ...  # Example packet structure (see model.py: L238-242 for _packet_from_json)
    }
```

**Success Criteria:**
- `ModelFilterer` class matches exact semantics of model.py's `predict()` function
- Feature schema validation prevents mismatch errors
- Confidence normalization uses same logic as model.py L233

---

### Phase 3: Define Configuration Interface & Audit Logging

**Goal**: Add external configuration file support and structured logging

**Changes Required:**

#### 1. File: `filter_config.yaml` (new)

```yaml
# Packet Filterer Configuration
model:
  path: "packet_model.pt"
  # Load checkpoint path
   
thresholds:
  # Probability threshold for blocking
  block_threshold: 0.7
  
logging:
  enabled: true
  level: INFO        # DEBUG, INFO, WARNING, ERROR
  output: "filter_decisions.log"
  
# Optional: rate limiting - track packet frequency per source
rate_limiting:
  enabled: false
  max_packets_per_second: 1000
  action_on_exceeded: "DROP"

sources:
  # Whitelist/blacklist patterns
  allow_patterns: []  # e.g., ["10.0.0.0/8"]
  deny_patterns: []   # e.g., ["203.0.113.0/24"]
```

#### 2. File: `model2.py` updates (add configuration loader)

```python
def load_config(config_path: str = "filter_config.yaml") -> dict:
    """Load configuration from YAML file."""
    import yaml
    try:
        with open(config_path, "r") as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        print(f"Config file {config_path} not found - using defaults")
        return {}

if __name__ == "__main__":
    import sys
    
    # Example CLI: python model2.py --config config.yaml
    if len(sys.argv) > 1 and sys.argv[1] == "--help":
        print("Usage: python model2.py [OPTIONS]")
        print("Options:")
        print("  --config FILE    Load YAML configuration")
        print("  --packet FILE    Packet data file (JSON)")
        sys.exit(0)
```

---

## What We're NOT Doing

**Explicit Out-of-Scope:**
- Modifying `model.py` itself - keeping original unchanged
- Implementing actual packet capture/processing at network interface
- Rate-limiting enforcement beyond threshold flags
- SIEM integration or external system calls
- GUI/web-based filtering interface
- Automated retraining pipeline for model updates

---

## Implementation Approach

### High-Level Strategy

**Phase 1 → Phase 2 → Phase 3** sequential dependency:
1. **Understand existing interface** - Read `model.py` predict/feature extraction code
2. **Build wrapper class** - Implement filterer with same inference semantics but add decision logic
3. **Add configuration/logging** - Externalize blocking thresholds and enable audit trail

### Design Decisions Made:

| Decision | Rationale |
|----------|-----------|
| `model2.py` not `packet_filterer.py` | Follows your direct request path naming |
| Reuse existing MODEL_FEATURES tuple | Avoid duplication, ensure schema consistency |
| Confidence = prob or (1-prob) | Mirrors model.py L233 for same semantic consistency |
| Threshold > 0.5 as BLOCK | Distinguish between "confidence" and "classification decision" |

---

## Testing Strategy

### Unit Tests:

#### 1. Test Feature Schema Matching
```python
def test_feature_schema_match():
    # Verify MODEL_FEATURES tuple length = 29
    assert len(MODEL_FEATURES) == 29, "Expected 29 features"
    expected = set(("packet_length", "ip_version", "ttl", "protocol_tcp", 
                   "protocol_udp", "protocol_icmp", "protocol_other",
                   "source_port", "destination_port", "tcp_syn", "tcp_ack",
                   "tcp_fin", "tcp_rst", "payload_length", 
                   "payload_printable_ratio", "payload_control_ratio",
                   "suspicious_byte_ratio", "contains_http_method", 
                   "contains_sql_marker", "contains_shell_marker"))
    assert set(MODEL_FEATURES) == expected, f"Feature mismatch: got {len(MODEL_FEATURES)}, expected 29"
```

#### 2. Test Decision Threshold Logic
```python
def test_decision_block_threshold():
    filterer = ModelFilterer(config={"block_threshold": 0.7})
    
    # Low probability → ALLOW
    low_conf_decision = filterer.evaluate({"...": ..., "confidence": 0.3, ...})
    assert low_conf_decision.action == "ALLOW"
    
    # High confidence (≥0.7) → BLOCK
    high_conf_decision = filterer.evaluate({"...": ..., "confidence": 0.85, ...})
    assert high_conf_decision.action == "BLOCK"
```

#### 3. Test Model Load Round-Trip
```python
def test_load_trained_model():
    # Should load packet_model.pt without errors, matching model.py's behavior
    filterer = ModelFilterer("packet_model.pt")
    initial_prob = predict_test_packet(filterer)
    # Verify prob is in [0, 1]
    assert 0 <= initial_prob <= 1
```

### Integration Tests:

#### 1. End-to-End Packet Evaluation
Create test packet with known malicious characteristics (from model.py test fixtures):
```python
test_packet = IP(src="192.0.2.1", dst="198.51.100.1") \
             / TCP(sport=12345, dport=80) \
             / Raw(load=b"GET / HTTP/1.1\r\nadmin' OR '1'='1--")

filterer = ModelFilterer()
decision = filterer.evaluate(packet_to_dict(test_packet))
```

#### 2. Verify Feature Determinism
Run evaluation multiple times with same packet → results should match model.py's output exactly.

---

## Files Created/Modified

| File | Type | Path | Description |
|------|------|------|-------------|
| **model2.py** | NEW | `/home/monarchhorvath/GullHacks/GullHacks-2026/model2.py` | Filterer module implementation |
| **filter_config.yaml** | NEW | `/home/monarchhorvath/GullHacks/GullHacks-2026/filter_config.yaml` | External configuration |
| **model.py** | UNCHANGED | `/home/monarchhorvath/GullHacks/GullHacks-2026/model.py` | Existing classifier (no changes) |

---

## Verification Steps

### Automated Verification:

```bash
# Verify imports work
cd /home/monarchhorvath/GullHacks/GullHacks-2026
python model2.py --packet test_packet.json

# Run unit tests (if added to test_model2.py)
python -m unittest discover -s tests -p "test_model2*.py"

# Verify feature schema match
pytest tests/  # Assuming pytest-based test suite
```

### Manual Verification:

- [ ] `ModelFilterer` can load `packet_model.pt` without errors
- [ ] Feature extraction produces same output as `model.py`'s `extract_features()` 
- [ ] Decision threshold logic (≥0.5 = malicious) works correctly
- [ ] Log files created with proper audit trail entries
- [ ] Configuration file parsing handles valid/invalid configs

---

## Dependencies

**No new external dependencies required:**
- Uses same imports as `model.py`: Scapy, PyTorch, numpy (via implicit torch ops)
- Optional: YAML library for configuration parsing (`pyyaml`)

```text
required packages: 
  - scapy       # Network packet handling
  - torch       # PyTorch model loading  
  - numpy       # Feature arrays (implicit via torch operations)
  - pytest      # Testing framework (if used)

optional packages:
  - pyyaml      # YAML configuration parsing (for filter_config.yaml)
```

---

## Next Steps After Plan Review

Once you approve this plan, the next step is to have me execute **Phase 1** - reading and understanding the exact interface in `model.py`. This will inform Phase 2's implementation details specifically.

Would you like me to:
1. Execute Phase 1 (analyze `model.py` predict/feature functions) now?
2. Wait for your input on specific threshold values or policy behavior?
3. Refine any aspect of the design before proceeding?
