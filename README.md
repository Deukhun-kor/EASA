# EASA — Edge-centric Adaptive Security API: simulator, cloud service and results

Code and data release for the manuscript

> D.-H. Kim and J. Kwak, EASA: An Edge-Centric Adaptive Security API for AIoT Devices, submitted to Sensors (MDPI), 2026.

Everything reported in the paper — every table, figure and number — is generated from the files in this
repository plus the public CIC IoT-DIAD 2024 dataset. The tag that corresponds to the submitted manuscript is
`v1.0-submission`.

## Contents

```
easa_sim/
├── config/default.yaml          every experimental parameter (= paper Table 7); the six main configurations
│                                (Table 5) under `configs:`; EASA_net_score (EASA−PH), EASA_no_energy and
│                                EASA_reset under `extra_configs:`
├── easa/                        simulator: data loaders, detector, trust engine, policy, cloud client, metrics
│   └── data/iotdiad.py          IoT-DIAD 2024 loader incl. the dominant-source labelling rule (paper §4.2)
├── cloud_service/               FastAPI cloud security service + Dockerfile + deploy.sh (Google Cloud Run)
├── scripts/
│   ├── run_experiments.py       grid runner (configurations × seeds → CSV, resumable)
│   ├── sweep.py                 one-at-a-time sensitivity sweep (Appendix C)
│   ├── make_figures.py          all LaTeX tables and PDF figures of the paper from the result CSVs
│   ├── audit_recovery.py        recovery audit on saved per-epoch traces (paper §5.7)
│   ├── label_sensitivity.py     label-rule sensitivity grid on the raw captures (paper Appendix E)
│   ├── label_sensitivity_working.py  the same grid applied to the working pool and replayed traces (Table A6)
│   ├── audit_protocol.py        implementation audit of the replay invariants (Appendix F)
│   ├── inspect_iotdiad.py       dataset inspection that produced the attacker designation
│   ├── download_iotdiad.py      fetches the flow-based IoT-DIAD release into data/
│   └── probe_rtt.py             baseline round-trip measurement to the deployed service
├── results/                     per-seed result CSVs of every experiment in the paper (see results/README.md)
├── figures/                     tables (.tex) and figures (.pdf) exactly as included in the manuscript
├── iotdiad_attackers.json       designated attacker addresses per attack type (paper Appendix A)
├── requirements.txt
├── CITATION.cff
└── LICENSE
```

## Data

CIC IoT-DIAD 2024, flow-based release (`AD_Flow-based-features`), from the Canadian Institute for Cybersecurity:
<https://www.unb.ca/cic/datasets/iot-diad-2024.html>. Please cite the dataset paper (Rabbani et al., IEEE Internet
of Things Journal 12(10), 2025, doi:10.1109/JIOT.2024.3522863). The dataset is not redistributed here;
`python scripts/download_iotdiad.py` places it under `data/IoT-DIAD-2024/flow/<Family>/<Attack>/*.csv`
(14.7 GB, 132 files). The `Label` column of this release holds the placeholder `NeedManualLabel`; row labels are
assigned by the dominant-source rule in `easa/data/iotdiad.py`, with the resulting attacker sets in
`iotdiad_attackers.json`.

## Environment

Python 3.11+, see `requirements.txt`. The reported runs used Windows 11, an NVIDIA RTX 5080 (PyTorch CUDA 12.8
build) and 32 GB RAM; CPU-only runs work but are slower. `B1_vnsf` needs `xgboost`.

```powershell
python -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install torch --index-url https://download.pytorch.org/whl/cu128
```

## Protocol versions

`config/default.yaml` encodes protocol v3, under which every number in the submitted manuscript was produced:
`replay.availability: end` (a flow record is replayed at its start timestamp + Flow Duration, capped at 120 s, i.e.
when an online extractor has its completed statistics) and `replay.calibration_fraction: 0.3333` (the first third
of each device's test timeline is used only by the benign calibration pass; the evaluation replays the remaining
two thirds). The earlier protocol v2 — completed statistics at flow start, calibration on the same traces from a
different phase — is reproduced with `--set replay.availability=start --set replay.calibration_fraction=0`; its
result files are kept under `results/protocol_v2/` for the record and are not used by any table of the paper.
Tables and figures of one paper version are never mixed across protocols. Every result row carries a `protocol_hash` of the data/replay/calibration config sections, and `run_grid` refuses to resume a CSV whose hash differs. `sweep.py` refuses to resume from a
result file of an older protocol; use `--fresh` after any protocol change (it also clears the `_sweep_tmp` cache).

## Reproducing the paper

All commands run from the repository root with `EASA_API_KEY` exported and `cloud.base_url` set (see below).
Results are written to `results/`; re-running a grid resumes (config, seed) pairs already present in the output
CSV (`--fresh` to ignore). The decisions of every cloud-dependent configuration are identical against the deployed
service and against the in-process mock (`--set cloud.transport=local`); only the `rtt_ms_*` / `n_calls` columns
differ, so the mock is sufficient for everything except the latency table.

| Paper section | Command | Output |
|---|---|---|
| Main experiment, cloud-path configurations (B2, B3, EASA−PH, EASA, 30 seeds, real cloud) | `python scripts/run_experiments.py --configs B2_rules B3_net_only EASA_net_score EASA_full --out results/v3c_main.csv` | `results/v3c_main.csv` |
| Main experiment, configurations without cloud calls (B0, B1, EASA−C) | `python scripts/run_experiments.py --configs B0_static B1_vnsf EASA_minus_C --out results/v3_main_nocloud.csv` | `results/v3_main_nocloud.csv` |
| Supplementary history-reset revision (§5.7, Table 15) | `python scripts/run_experiments.py --configs EASA_reset --out results/v3c_reset.csv` | `results/v3c_reset.csv` |
| Cloud outage (§5.5) | `python scripts/run_experiments.py --configs EASA_full --set cloud.outage.enabled=true --out results/v3c_outage.csv` | `results/v3c_outage.csv` |
| Low battery (§5.6), incl. the selector-only ablation | `python scripts/run_experiments.py --configs EASA_full B3_net_only EASA_no_energy --set posture.init_energy_range=[0.10,0.35] --out results/v3c_lowbattery.csv` | `results/v3c_lowbattery.csv` |
| Recovery / pending audit on saved traces (§5.7, Table 14) | `python scripts/audit_recovery.py results/traces/v3c_main` | stdout (`results/log_audit_v3c_main.txt`) |
| Label-rule sensitivity (Appendix E) | `python scripts/label_sensitivity.py --out results/label_sensitivity.csv` | `results/label_sensitivity.csv` |
| Label-rule sensitivity on the working data (Appendix E, Table A6) | `python scripts/label_sensitivity_working.py --grid results/label_sensitivity.csv --out results/label_sensitivity_working.csv` then `python scripts/make_labelsens_tables.py results/label_sensitivity_working.csv --out figures/tab_labelsens_working.tex` | `results/label_sensitivity_working.csv`, `figures/tab_labelsens_working.tex` |
| Replay-protocol implementation audit (Appendix F, Table A7) | `python scripts/audit_protocol.py > results/log_audit_protocol.txt` | `results/log_audit_protocol.txt` |
| Sensitivity (Appendix C, in-process mock) | `python scripts/sweep.py --fresh --seeds 10 --out results/v3_sensitivity.csv` | `results/v3_sensitivity.csv` |
| Tables and figures | `python scripts/make_figures.py results/final_main_v3.csv --outage results/v3c_outage.csv --lowbattery results/v3c_lowbattery.csv --reset results/final_supp_reset_v3.csv --sens results/v3_sensitivity.csv --traces results/traces/v3_main --out figures` | `figures/*.tex`, `figures/*.pdf`, `figures/summary.md` |

`results/final_main_v3.csv` is the concatenation of the four cloud-path configurations from `v3c_main.csv` and the
three configurations without cloud calls (B0, B1, EASA−C), plus a `source` column; `final_supp_reset_v3.csv` holds
the EASA_reset rows. The label-sensitivity table (`figures/tab_labelsens.tex`) and the audit table of the paper are
derived from `results/label_sensitivity.csv` and `results/log_audit_v3c_main.txt` respectively.

### Cloud service

The main, outage and low-battery experiments call a FastAPI service deployed on Google Cloud Run
(`asia-northeast3`, 1 vCPU, 512 MiB, min = max instances = 1). To redeploy:

```bash
export EASA_API_KEY=$(openssl rand -hex 24)        # keep it out of git
cd cloud_service && ./deploy.sh <gcp-project-id>
```

then set `cloud.base_url` in `config/default.yaml` (or `--set cloud.base_url=...`) and export `EASA_API_KEY`
before running. With `--set cloud.transport=local` every experiment runs against the in-process mock of the
same service (no network, identical aggregation arithmetic); this is how the sensitivity sweep was run, and every
cloud-path configuration of the main, outage and low-battery experiments was run both ways with identical
per-seed results.

## Seeds, randomness and what is fixed

The data split and subsampling are seed-0 fixed (one pool for every configuration and seed). Seed k
fixes the campaign schedule, replay phases, posture draws, detector initialisation and batch order; the
cloud service is reset at the start of every run. Configurations run on the same seed therefore face the
same attacks on the same devices, which is what makes the paired tests in the paper valid.

## Citation

See `CITATION.cff`. Until the paper is published please cite this repository by its tag and commit.

## License

MIT (see `LICENSE`). The IoT-DIAD 2024 dataset is subject to the terms of the Canadian Institute for
Cybersecurity.
