---
date: 2026-11-07T16:22:15-05:00
git_commit: HEAD (no commits yet - untracked repository)
branch: main
repository: GullHacks-2026
topic: Packet-Level Maliciousness Classifier using MLP and Scapy
tags: [research, codebase, model]
status: complete
---

# Research: Packet-Machine-Learning Model Codebase Study

## Research Question
Study the ML model code including features, architecture, training, inference, and testing infrastructure in `model.py`.

## Summary
A packet-level maliciousness classifier for network traffic analysis. Uses Scapy for packet parsing and PyTorch MLP (3-layer NN with ReLU) for binary classification of benign vs malicious packets. No git history yet - project initialized fresh.

## Detailed Findings

### Core Architecture Components

#### **Feature Extraction Pipeline** (`model.py:49-98`)
- `_payload()` function extracts `Raw` layer payload from Scapy packet (L50-52)
- `extract_features()` converts packets to feature vectors (29 features total)
  - Protocol detection (TCP/UDP/ICMP/other)
  - Port analysis (source, destination)
  - TCP flag flags analysis
  - Payload ratios: printable/control/suspicious byte fractions
  - Semantic pattern detection (HTTP methods, SQL injection, shell commands)
  
#### **Model Architecture** (`model.py:101-113`)
- `PacketMLP` class: PyTorch Sequential neural network
- Input → Linear(29→32) → ReLU → Linear(32→16) → ReLU → Linear(16→1)
- Output: sigmoid probability for benign/malicious classification

#### **Training Pipeline** (`model.py:183-207`)
- `train()` function: supervised training with Adam optimizer
- BCEWithLogitsLoss (binary cross-entropy with logits)
- Learning rate 0.01, default 120 epochs
- Per-class scaling normalization using mean/std from feature matrix

#### **Inference & Deployment** (`model.py:210-235`)
- `save_model()` / `load_model()`: PyTorch checkpoint I/O
- `predict()` function: zero-graph inference with normalized features
- Returns `Prediction` dataclass (label, confidence, feature dict)

### Data Handling Components

#### **Data Generation** (`model.py:126-157`)
- `generate_starter_data()`: deterministic synthetic training data
  - Samples per class: 64 default
  - Random seed reproducible features generation
  - Binary classification (label 0=benign, 1=malicious)

#### **CSV I/O** (`model.py:160-180`)
- `write_feature_csv()` / `read_feature_csv()` for training data storage
- Schema validation required columns and both classes present

### Command-Line Interface (`model.py:246-275`)
- Arguments: `--model`, `--starter-data`, `--train-csv`, `--pcap`, `--packet-json`
- Training path: CSV input → feature matrix → model weights save
- Inference path: `.pt` model + packet/PCAP → JSON predictions

### Testing Infrastructure (`tests/test_model.py`)
- Unit tests for feature stability and round-trip training/inference
- Uses Scapy layers (IP, TCP, Raw) directly for test packets

## File List & Structure

```
GullHacks-2026/
├── model.py           [275L, 18F] - Core ML/model code
├── tests/             [41L, 3C]
│   └── test_model.py  [41L] - Unit tests
├── packet_model.pt    [0B]      - Trained model checkpoint
├── requirements.txt   [4L]
├── main.py            [25L]     - Alternative entry point
├── run.sh             [78B]      - Shell script runner
├── sniffingexp.ipynb  [62L]      - Jupyter notebook experiment
└── README.md          [0]       - Documentation stub
```

## Code Reference Summary

**Features definition:** `model.py:18-39` (29 features)  
**Prediction class:** `model.py:43-47` (dataclass schema)  

**Core model:** `model.py:101-113` (PacketMLP architecture)  

**Feature extractor:** `model.py:55-98` (packet → feature matrix)  

**Training function:** `model.py:183-207` (Adam optimizer, BCELoss)  

**Save/Load:** `model.py:210-222` (torch checkpoint I/O with validation)  

**Predict:** `model.py:225-235` (normalized inference with sigmoid)  

## Open Questions

1. **Git History**: Repository has no commits yet (untracked state). Is this intentional or work in progress?
2. **Data Source**: Where does packet JSON come from for real-world data? What's the pcap file format/origin?
3. **main.py role**: Separate `main.py` exists - purpose unclear compared to argparse CLI entry point in model.py
4. **Requirements**: Dependencies (numpy, pandas, torch, scapy) listed but not validated in this repo context

### Technical Observations
- Code is clean and production-ready: type annotations used throughout
- Feature schema is hard-coded constant → prevents accidental mismatches between training/inference
- Random seed (7) used for reproducible feature generation and model training
- No data augmentation or validation split in current implementation
