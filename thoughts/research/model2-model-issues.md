---
date: 2026-11-07T21:13:50-05:00
git_commit: 806b2fd7c1816f294a061048dc380189b03f7b86
branch: main
repository: GullHacks-2026
topic: "Research Issues in model2.py and Related Problems in model.py"
tags: [research, codebase, python, packet-classification]
status: complete
---

# Research: Issues in model2.py Located in model.py Implementation

## Research Question
Identify implementation issues in @file:model2.py that stem from problems in the @file:model.py source code. Only document what exists; do not suggest changes or improvements.

## Summary

### Critical Issues Found (model2.py):
1. **Major Syntax Error** - Lines 340-352 contain broken duplicate code with undefined variables (`malicious_packet_result`, `features`) that was incorrectly pasted during testing

2. **Missing Variable Definition** - The "Malicious Packet Evaluation Result" test case at L333-347 never successfully defines `malicious_packet_data` or the corresponding result from `filterer.evaluate()` due to broken code structure

### Potential Schema Mismatch Issues:
1. **Feature Extraction Assumption** - model2.py assumes FEATURE_NAMES consistency between model.py (L18-39) and PACKET_NAMES (L224-245), but uses fallback to empty tuple if verification fails at L107

2. **Confusion in Confidence Calculation** - A corrupted line L345 attempts inline confidence calculation without using the proper `max(prob, 1-prob)` formula from model.py L233

### How They Relate:
- model2.py (L214) imports and uses `extract_features()` from model.py directly via internal import (L138)
- Model loading is consistent between both files (model2.py L97-99 calls `load_model()`)
- Feature extraction logic in model2.py (L154-164) mirrors model.py's predict implementation

## Detailed Findings

### Files Analyzed:
- **@file:model2.py** - Packet Filterer Module with enforcement capabilities
- **@file:model.py** - Base packet classification model

### Key Connections and Issues:

#### Issue 1: Broken Test Code (model2.py Line 339+)
| Element | Location in model2.py | Status |
|---------|----------------------|--------|
| `benign_decision` variable | L321, properly defined and used via `filterer.evaluate()` | ✅ Working |
| `malicious_packet_result` variable | Never defined - line references L343 | ❌ Undefined |
| Inline feature matrix at L345 | Corrupted - no proper model inference chain | ❌ Broken syntax |

#### Issue 2: Feature Schema Verification Risk (model2.py Lines 103-112)
```python
try:
    test_packet = Packet()
    features_result = extract_features(test_packet)
    self.feature_names = tuple(features_result.keys())
    assert tuple(metadata["feature_names"]) == self.feature_names, \
        f"Feature schema mismatch in checkpoint"
except Exception:  # Falls back to empty tuple which may cause failures later
    self.feature_names = ()
```

**Risk:** Empty `feature_names = ()` will break packet evaluation if PACKET_NAMES doesn't match metadata["feature_names"] exactly.

#### Issue 3: Confidence/Probability Mismatch (model2.py Line 345 vs model.py Line 233)

| File | Location | Formula Used | Correct? |
|------|----------|--------------|----------|
| model.py | L233 | `probability if probability >= 0.5 else 1.0 - probability` | ✅ Yes |
| model2.py | L172 | `max(prob, 1.0 - prob)` | ✅ Equivalent |
| model2.py (corrupted) | L345 | Manual inline sigmoid calculation without confidence inversion | ❌ No |

## Code References

### model.py (Reference Implementation):
- `FEATURE_NAMES` tuple at **L18-39** - Defines 20 features for classification
- `extract_features()` function at **L55-98** - Extracts feature vector from Scapy packet
- `predict()` method at **L225-235** - Returns Prediction with proper confidence calculation at L233: `probability if probability >= 0.5 else 1.0 - probability`
- `load_model()` at **L214-222** - Loads checkpoint, validates schema matching

### model2.py (Derived Implementation):
- Imports `extract_features`, `load_model`, `predict` from model.py (L21-24)
- `PACKET_NAMES` tuple at **L224-245** - Same 20 features as FEATURE_NAMES in model.py
- Model loading attempt at **L97-99**: `self.model, metadata = load_model(model_path)`
- Feature extraction verification (risky) at **L103-113**
- Test case with broken code starting at **L333-352**

### model.py - Predict Implementation Flow (for Reference):
```python
def predict(packet: Packet, model: PacketMLP, metadata: dict) -> Prediction:
    1. features = extract_features(packet)           # L226
    2. values = np.asarray([[features[name] for name in FEATURE_NAMES]], ...)  # L227
    3. normalized = (values - metadata["mean"]) / metadata["scale"]     # L228
    4. probability = float(torch.sigmoid(model(torch.from_numpy(normalized))).item())  # L230
    5. confidence = probability if probability >= 0.5 else 1.0 - probability   # L233 ← This pattern is corrupted in model2.py line 345
```

## Open Questions

1. **Feature Alignment** - Have the FEATURE_NAMES (L18-39) and PACKET_NAMES (L224-245) been updated identically since their last synchronization? Any mismatches would cause silent failures.

2. **Malicious Packet Test Case Original Code** - The code at L333 is incomplete. The original `malicious_packet_data` definition should have included SQL injection markers or shell command indicators similar to the benign packet but missing due to copy-paste failure.

3. **Schema Versioning Mismatch Risk** - If model.py updates FEATURE_NAMES (e.g., adds a new feature like Lx40) but PACKET_NAMES in model2.py wasn't updated synchronously, load_model would validate against metadata["feature_names"] and reject the model. The code doesn't have clear error handling for this scenario beyond the try/except at L103-113 which falls back to empty tuple.

4. **Line 345 Intent** - The corrupted inline expression at L345 appears to be attempting some form of normalized feature computation but has broken syntax: `(np.asarray(metadata["scale"], dtype=np.float32) if all(metadata.get(k) is not None and k in metadata for k in ["mean", "scale"])) else np.ones_like(metadata["mean"])` - the logic doesn't properly compute the difference or apply the correct shape transformation that model.py uses.
