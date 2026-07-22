# CAVDBG

CAVDBG is a dynamic state-aware agent for automated vulnerability repair. It uses debugger-observed suspicious states, angelic/demonic interventions, counterfactual angelic invariants (CAIs), and replay validation to generate patches for C/C++ vulnerability.



## Repository layout

- `stalker/`: CAVDBG agent implementation.
- `scripts/`: launch, batch, validation, and semantic-security judging scripts.
- `dataset/`: ARVO-Rand 190-instance IDs and JSON profiles.
- `experiments/`: paper experiment data organized by RQ.
- `tests/`: unit tests for core routing, debugging, constraint, patch, and judging utilities.

## Prerequisites

The full repair workflow runs inside ARVO benchmark Docker images. You need:

- Linux with Docker available to the current user.
- Python 3.10+ virtualenv or conda environment.
- `clangd`, mounted into benchmark containers.
- `lldb-mi`, mounted into benchmark containers.
- ARVO vulnerable Docker images for the target instance IDs, named by the launcher as `arvo:<id>-vul` unless your local Docker setup aliases that image name.
- LLM API credentials in `workspace/llm.yml`.

The included `dataset/` directory contains ARVO metadata, not the Docker images or PoC corpora.

## Install

Run all commands from this `CAVDBG/` directory. The shell launchers use relative paths such as `./scripts/utils.sh`.

```bash
cd CAVDBG
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Prepare tool paths:

```bash
mkdir -p opt
# Put clangd under opt/clangd so opt/clangd/bin/clangd exists.
# Put lldb-mi under opt/lldb-mi so opt/lldb-mi/bin/lldb-mi exists.
```

`lldb-mi` is not distributed by LLVM official releases. Use a local compatible build and point `LLDBMI_PATH` to it.

## Configure CAVDBG

Edit `stalker.yml`:

```yaml
STALKER_PATH: ./stalker
CLANGD_PATH: ./opt/clangd
LLDBMI_PATH: ./opt/lldb-mi
PYTHON_PATH: /absolute/path/to/CAVDBG/.venv
```

Create `workspace/llm.yml`:

```bash
mkdir -p workspace
```

```yaml
llm:
  select: deepseek-v4-flash
  profiles:
    - name: deepseek-v4-flash
      base_url: https://your-llm-endpoint/v1
      api_key: YOUR_API_KEY
      model: deepseek/deepseek-v4-flash
      temperature: 0.2
```

You can add multiple profiles and switch the active model with `llm.select`.

## Run CAVDBG on one ARVO instance

Pick an ID from:

```bash
head dataset/arvo_190_ids.txt
```

Run the full repair workflow:

```bash
./scripts/launch.sh -f stalker.yml -t 42501162
```

Outputs are written to:

```text
workspace/logs/<id>/
workspace/results/<id>/
```

Use `--run-suffix` to avoid overwriting an earlier run:

```bash
./scripts/launch.sh -f stalker.yml -t 42501162 --run-suffix trial1
```

Keep the container alive for debugging:

```bash
./scripts/launch.sh -f stalker.yml -t 42501162 -d
```

## Run the ARVO-Rand 190 batch

The paper's ARVO-Rand 190 subset is:

```text
dataset/arvo_190_ids.txt
```

Run with 4 concurrent jobs:

```bash
./scripts/batch_launch.sh \
  -f stalker.yml \
  -t dataset/arvo_190_ids.txt \
  -r workspace/batch_logs/arvo_190_cavdbg \
  -j 4 \
  --run-suffix arvo190
```

Increase `-j` only if your machine has enough CPU, memory, Docker capacity, and API quota.

## Ablation modes

The launchers support the ablations used in the paper:

```bash
# No angelic counterfactual mutation/search.
./scripts/batch_launch.sh -f stalker.yml -t dataset/arvo_190_ids.txt \
  -r workspace/batch_logs/arvo_190_no_angelic -j 4 \
  --ablation-state-only-no-angelic

# DebugAgent angelic evidence directly to PatchAgent; no CAI construction.
./scripts/batch_launch.sh -f stalker.yml -t dataset/arvo_190_ids.txt \
  -r workspace/batch_logs/arvo_190_no_cai -j 4 \
  --ablation-no-cfc

# Observation-only LLDB DebugAgent directly to PatchAgent.
./scripts/batch_launch.sh -f stalker.yml -t dataset/arvo_190_ids.txt \
  -r workspace/batch_logs/arvo_190_lldb_only -j 4 \
  --ablation-lldb-only
```

Use only one ablation flag at a time.

## Validate existing ARVO patches

For CAVDBG ARVO, a generated patch exists only after the repair pipeline has already replayed the PoC successfully. If you need independent replay validation for a patch JSON file, use:

```bash
python3 scripts/arvo_validate_patches.py \
  --arvo-raw path/to/arvo_raw_manifest.jsonl \
  --patch-json path/to/patch.jsonl \
  --output-dir workspace/arvo/validation/my_run \
  --workers 8
```

The expected patch JSONL format is:

```json
{"instance_id": "42501162", "model_patch": "diff --git ..."}
```

## Run semantic-security correctness judging

The SSC judge compares candidate patches against vulnerability evidence and reference-fix semantics. The panel wrapper can run one or more configured judges:

```bash
./scripts/run_semantic_security_panel.sh \
  --output-dir workspace/secbench/semantic_judge/my_panel \
  --judge deepseek-v4-pro \
  -- \
  --secbench-raw path/to/secbench_raw_eval-cve.jsonl \
  --patch-json path/to/patch.jsonl \
  --validation-report path/to/report.jsonl \
  --source-cache-dir workspace/secbench/source_cache \
  --workers 20 \
  --max-context-chars 20000 \
  --max-diff-chars 120000
```

With no `--judge` option, the wrapper runs the configured three-judge panel and aggregates by strict majority.


## Paper experiment data

Experiment data is under `experiments/`:

- `experiments/rq1_overall/`: Table III, Fig. 3 SSC label counts, Table IV manual audit, and patch/report artifacts where available.
- `experiments/rq2_ablation/`: Table V(a) ablation data.
- `experiments/rq3_cai_analysis/`: Table V(b) CAI class distribution.



## Run tests

```bash
python -m unittest discover -s tests
```



## Additional artifacts

Baseline outputs and detailed CAVDBG trajectories are hosted separately.
