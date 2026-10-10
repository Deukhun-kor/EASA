# easa_sim — Edge-centric Adaptive Security API simulator

Trace-driven simulator for the paper "EASA: An Edge-Centric Adaptive Security API for AIoT Devices" (Sensors, MDPI).
The top-level `README.md` of the repository gives the reproduction table for every result in the paper; this file is
the quick reference to the code.

```
easa_sim/
├── config/default.yaml        all experimental parameters (= paper's setup table)
├── easa/
│   ├── data/   pool.py, ciciot.py (CIC-IoT-2023), toniot.py (TON_IoT), synthetic.py (smoke test)
│   ├── detector.py   MLP (torch/CUDA, FedAvg-able) · XGBoost · Rules
│   ├── posture.py    device energy/CPU/link/integrity model  (S_pos)
│   ├── trust.py      Eqs. (1)–(4)                              (T_d)
│   ├── policy.py     L0–L3 hysteresis + energy-aware step-up   (PDP/PEP)
│   ├── cloud.py      HttpCloud (real) · LocalCloud (mock) · NullCloud
│   ├── scenario.py   campaigns: traffic / FirmwareTamper / CredentialReplay, cross-site holdout
│   ├── gateway.py    Algorithm 1 per epoch, batched inference
│   ├── metrics.py    F1(L2), FQR, TTC, overhead, cross-site, replay catch
│   └── runner.py     seeds × configurations → CSV (+ traces)
├── scripts/run_experiments.py   grid runner (--set dotted overrides, --fresh; refuses cross-protocol resumes)
├── scripts/sweep.py             one-at-a-time sensitivity sweep (--fresh after a protocol change)
├── scripts/make_figures.py      LaTeX tables, Wilcoxon+Holm, PDF figures (+ --lowbattery, --reset)
├── scripts/audit_recovery.py    recovery / pending audit on saved traces
├── scripts/audit_protocol.py    replay-protocol implementation audit (paper Appendix F)
├── scripts/label_sensitivity.py            label-rule sensitivity on the raw captures (Appendix E)
├── scripts/label_sensitivity_working.py    the same on the working pool and replayed traces (Table A6)
├── scripts/make_labelsens_tables.py        Table A6 from the CSV above
├── scripts/probe_rtt.py         baseline RTT to the Seoul deployment
└── cloud_service/               FastAPI service + Dockerfile + deploy.sh (Cloud Run asia-northeast3)
```

## Quick start

```bash
pip install -r requirements.txt
pip install torch --index-url https://download.pytorch.org/whl/cu128     # RTX 5080

# smoke test (no data, no cloud) ~3 s/run
python scripts/run_experiments.py --set data.source=synthetic --set cloud.mode=local --seeds 2 --configs EASA_full B3_net_only

# real data + real cloud
export EASA_API_KEY=...   # same value used in deploy.sh
python scripts/run_experiments.py --set cloud.base_url=https://easa-cloud-XXXX-asia-northeast3.run.app
python scripts/make_figures.py results/easa_main.csv --out figures
```

Data layout expected:
```
data/CICIoT2023/csv/part-*.csv
data/TON_IoT/Train_Test_Network.csv
data/TON_IoT/Train_Test_IoT_*.csv
```

## Configurations (Table 3)
`B0_static, B1_vnsf, B2_rules, B3_net_only, EASA_minus_C, EASA_full` — select with `--configs`.
Every other knob is a dotted override, e.g. `--set trust.w_net=0.7 --set policy.h_epochs=10`.

## Notes
* `B1_vnsf` needs `xgboost`; everything else runs on scikit-learn if torch/xgboost are absent.
* Cloud state is reset (`POST /reset`) at the start of every seed so runs are independent.
* Seed 0 of each configuration saves a full per-epoch trace under `results/traces/` for figures.
