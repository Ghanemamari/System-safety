# Iteration 4B — Llama 3.1 8B Clean Capability Gate

## Decision

`MODEL_ACCESS_BLOCKED`

The model card metadata is publicly visible, but the checkpoint repository is manually gated. Runpod has no configured Hugging Face credential, and a HEAD-only request for the repository's `config.json` returned HTTP 401. No model files were downloaded and no inference was run.

## Model preflight

- Model: `meta-llama/Llama-3.1-8B-Instruct`
- Exact revision: `0e9e39f249a16976918f6564b8830bc894c89659`
- Access: manual Hugging Face gate
- Requirement: accept the Meta Llama 3.1 license and authenticate with an account granted access
- License metadata: `llama3.1`
- Parameter count: 8,030,261,248 BF16 parameters
- Checkpoint weights: 16,060,556,376 bytes across four safetensors shards
- Raw BF16 parameter footprint: 14.958 GiB

## Resource preflight

- GPU: NVIDIA RTX A5000
- Total VRAM: 24,564 MiB
- Free VRAM before any download: 24,112 MiB (23.547 GiB)
- The checkpoint's raw weights theoretically fit in free VRAM.
- Runtime fit was not tested because model access is blocked.

## Frozen methodology integrity

- Frozen task file: `data/iteration2a/capability_tasks.json`
- SHA-256: `44b3780a971bbc9a18377521823814d5c3195ba2595c74cfc80a98b79b8812fb`
- Scope: 25 unique development tasks
- Coverage: 5 read, 5 write, 15 no-action
- Pre-experiment regression suite: 63/63 PASS in 13.668 seconds
- Intended protocol: Iteration 4A P4/native-chat-template clean gate, deterministic BF16 CUDA inference

## Scope confirmation

- Model downloads: 0
- Capability runs: 0
- Attack runs: 0
- Validation tasks used: no
- Frozen final-test tasks used: no
- Substitute models used: no

The experiment stopped at the mandatory access gate.
