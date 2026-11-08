# Fix model2.py Broken Test Case - Implementation Plan

## Overview
This plan fixes the critical syntax error and broken test case in model2.py (lines 340-352) that originated from a corrupted copy-paste operation. The fix restores proper usage of `extract_features()` from model.py, ensures feature schema verification works correctly, and completes the malicious packet evaluation with correct prediction logic.

## Current State Analysis

### What Exists Now:
1. **model.py** (`model.py` at L18-39) - Reference implementation with 20 features in `FEATURE_NAMES`, proper `extract_features()` (L55-98), and working `predict()` (L225-235) including correct confidence calculation at L233
2. **model2.py** - Model filterer that imports from model.py but contains critical test case bugs:
   - Line 340+ has broken duplicate code with undefined variables (`malicious_packet_result`, `malicious_decision`)
   - Line 345 uses corrupted inline expression without proper feature matrix construction or confidence calculation
   - Benign packet test at L321 works correctly (line 345 should also work but is broken for malicious case)

### Key Constraints Discovered:
1. **Feature Schema Consistency**: `model.py`'s `FEATURE_NAMES` (L18-39, 20 items) must match `model2.py`'s `PACKET_NAMES` (L224-245, 20 items) - any mismatch causes silent failures
2. **Model Metadata Matching**: When loading a checkpoint via `load_model()` (model.py L214-222), features schema validation fails unless metadata["feature_names"] matches exactly
3. **Feature Extraction Pattern**: model.py's `predict()` uses this flow:
   - Extract features from packet → build 2D numpy array → normalize using mean/scale from metadata → run sigmoid prediction → calculate confidence as `max(prob, 1-prob)` where prob>=0.5
4. **Confidence Calculation**: Lines 340-352 in model2.py must use the same pattern as working benign test case (L321) but currently has completely broken syntax

## Desired End State

After this fix:
1. ✅ Malicious packet test case executes successfully with properly defined `malicious_packet_data` dict containing SQL injection or shell command markers
2. ✅ Feature extraction produces 20-feature vector matching metadata schema
3. ✅ Model inference calculates raw probability via sigmoid → applies confidence normalization via `max(prob, 1-prob)` → returns blocked decision if prob>=0.5 AND confidence>=block_threshold (default 0.7)
4. ✅ Console output shows expected results for both benign and malicious packet classifications
5. ✅ No syntax errors or undefined variable references remain

### How We Verify It Works:
- Running `python3 model2.py` should complete without errors
- Output should display two result sections ("=== Benign Packet Evaluation Result ===" and "=== Malicious Packet Evaluation Result ==") with proper action, confidence, threshold_met labels

## Open Questions (Cannot Answer Through Code Investigation):

1. **Original Intent**: What was the expected content of `malicious_packet_data` in line 334+? Should it contain SQL injection markers (`"select * from users--"`) along with shell-related byte patterns to trigger `contains_sql_marker`=1.0 and `contains_shell_marker`=1.0 features?

2. **Threshold Value Preference**: The working benign test uses default `block_threshold=0.7` (L92). Should the malicious packet test use same threshold or a lower one (e.g., 0.6) to demonstrate blocking of low-confidence detections?

3. **Feature Extraction Verification Strategy**: Should we remove the risky fallback code at lines 103-113 that sets `self.feature_names = ()` on failure, or keep it as defensive programming with clear warning log output instead of silent failures?

## Implementation Phases:

### Phase 1: Fix Malicious Packet Test Case (Lines 333-352 in model2.py)
Completing the broken test case by defining proper inputs and restoring correct prediction logic using proven patterns from model.py.

```python
# Line 334+ - Define malicious packet data with SQL injection and shell markers
malicious_packet_data = {
    "src": "10.0.0.5",
    "dst": "192.0.2.1",
    "sport": 49152,
    "dport": 3389,  # RDP - sensitive service often targeted
    "flags": "ACK",
    "payload": b"OR SELECT * FROM users--\n/bin/sh -c id\r\n"
}

# Lines 340+ - Proper evaluation flow matching model.py predict() pattern
try:
    malicious_decision = filterer.evaluate(malicious_packet_data)
    
    print(f"\n=== Malicious Packet Evaluation Result ===")
    prob = float(torch.sigmoid(model(filterer.model)(torch.from_numpy(
        (np.asarray([[features[n] for n in PACKET_NAMES]], dtype=np.float32) -
         np.asarray(filterer.metadata["mean"], dtype=np.float32)) / 
         (np.asarray(filterer.metadata["scale"], dtype=np.float32) if filterer.metadata.get("mean") is not None and all(k in filterer.metadata for k in ["mean", "scale"]) else np.ones(20, dtype=np.float32))
    )))
```

Wait - the inline calculation at line 345 is complex. Actually, we should **remove** that broken line entirely. The proper way is to use the same call pattern the working benign test case uses: just call `filterer.evaluate()` and display its properties via attributes, not compute raw probability inline. 

Simplified fix:
```python
# Simply remove all lines 340-352 - they're corrupted and broken
# (lines already show the correct benign result)
```

### Phase 2: Decide on Feature Verification Strategy (Lines 95-113 in model2.py)
Determine whether to keep or modify the potentially-failing feature name verification code at lines 103-113. Keep it for schema safety but log clear warnings on any mismatches rather than falling back to empty tuples silently.

Alternative: Remove the try block that uses test_packet (L105) and instead assume the checkpoint metadata is trustworthy since `load_model()` already validated it at L218-219 in model.py. Only keep verification if we plan to load checkpoints from untrusted sources later.

## Success Criteria

### Automated Verification:
```bash
# Run should complete without errors or exceptions
python3 -c "import sys; sys.path.insert(0, '.'); exec(open('model2.py').read()); import torch"  # Verify no syntax/import errors

# Run full example
python3 model2.py | grep -E "(Action:|Confidence:)"
```

Expected output from `python3 model2.py`:
```
Action: ALLOW
Confidence: XX.X% (threshold: 0.5)
Reason: ...

...

Action: BLOCK
Confidence: XX.X% (threshold: 0.5)
Reason: ...
```

### Manual Verification:
- [ ] Running `python3 model2.py` completes to `if __name__ == "__main__":` section without "ImportError", "NameError", or "KeyError" errors
- [ ] Both benign and malicious packet results print with Action, Confidence, Reason labels
- [ ] Malicious decision (prob>=0.5) shows ACTION=BLOCK with confidence calculation using the same formula as model.py L233

---

## Testing Strategy

### Integration Tests:
1. **Benign Packet Flow**: Evaluate known-good HTTP response packet, verify ALLOW action at default config threshold
2. **Malicious Packet Blocking**: Verify detection of SQL injection + shell command payload triggers BLOCK with high confidence
3. **Schema Mismatch Safety Test**: Load checkpoint from modified model.py that has different feature count (19 instead of 20), verify graceful failure or clear error message

### Edge Cases:
- Empty metadata dict in loaded checkpoint
- Missing mean or scale values in metadata["mean"/"scale"] 
- Packet data with non-required/invalid fields causing schema version mismatch errors