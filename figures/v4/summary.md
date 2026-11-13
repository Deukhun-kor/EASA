# Results summary
source: results_v4/v4_main.csv, 210 runs, 30 seeds

## Main table
| Configuration | F1 ($L_2$) | FPR | Recall (in-dist.) | Recall (cross-site) | Activation | TTC p50 (s) | False quarantine | Re-auth / dev-h | Replay catch (all runs) |
|---|---|---|---|---|---|---|---|---|---|
| B0 static | 0.000 ± 0.000 [0.000, 0.000] | 0.000 ± 0.000 [0.000, 0.000] | 0.000 ± 0.000 [0.000, 0.000] | 0.000 ± 0.000 [0.000, 0.000] | 0.000 ± 0.000 [0.000, 0.000] | -- | 0.000 ± 0.000 [0.000, 0.000] | 0.000 ± 0.000 [0.000, 0.000] | 0.000 ± 0.000 [0.000, 0.000] |
| B1 VNSF | 0.640 ± 0.099 [0.606, 0.674] | 0.050 ± 0.026 [0.041, 0.060] | 0.872 ± 0.061 [0.850, 0.892] | 0.673 ± 0.187 [0.606, 0.738] | 0.807 ± 0.089 [0.776, 0.839] | 33 ± 17 [27, 39] | 0.071 ± 0.031 [0.060, 0.082] | 0.000 ± 0.000 [0.000, 0.000] | 0.201 ± 0.215 [0.127, 0.282] |
| B2 rules | 0.257 ± 0.154 [0.203, 0.311] | 0.032 ± 0.030 [0.022, 0.043] | 0.163 ± 0.137 [0.121, 0.216] | 0.119 ± 0.147 [0.070, 0.176] | 0.282 ± 0.157 [0.227, 0.335] | 94 ± 132 [52, 143] | 0.054 ± 0.046 [0.039, 0.071] | 0.000 ± 0.000 [0.000, 0.000] | 0.272 ± 0.328 [0.163, 0.390] |
| B3 net-only | 0.759 ± 0.101 [0.723, 0.794] | 0.017 ± 0.015 [0.011, 0.022] | 0.811 ± 0.097 [0.777, 0.843] | 0.763 ± 0.107 [0.723, 0.798] | 0.833 ± 0.093 [0.799, 0.865] | 42 ± 18 [36, 48] | 0.017 ± 0.022 [0.010, 0.025] | 0.200 ± 0.099 [0.165, 0.233] | 0.213 ± 0.246 [0.126, 0.300] |
| EASA-C | 0.674 ± 0.102 [0.640, 0.711] | 0.024 ± 0.022 [0.017, 0.032] | 0.803 ± 0.092 [0.773, 0.836] | 0.560 ± 0.203 [0.484, 0.629] | 0.744 ± 0.120 [0.698, 0.785] | 42 ± 29 [34, 53] | 0.020 ± 0.031 [0.011, 0.032] | 0.241 ± 0.068 [0.217, 0.266] | 0.178 ± 0.240 [0.101, 0.268] |
| EASA-PH | 0.815 ± 0.090 [0.783, 0.846] | 0.017 ± 0.015 [0.012, 0.022] | 0.810 ± 0.095 [0.776, 0.843] | 0.765 ± 0.107 [0.727, 0.801] | 0.926 ± 0.081 [0.897, 0.953] | 40 ± 18 [34, 47] | 0.017 ± 0.022 [0.009, 0.025] | 0.199 ± 0.099 [0.165, 0.233] | 0.811 ± 0.308 [0.697, 0.912] |
| EASA | 0.764 ± 0.102 [0.728, 0.802] | 0.020 ± 0.018 [0.015, 0.027] | 0.762 ± 0.124 [0.715, 0.803] | 0.687 ± 0.122 [0.644, 0.729] | 0.887 ± 0.091 [0.853, 0.918] | 47 ± 24 [39, 55] | 0.016 ± 0.022 [0.009, 0.024] | 0.240 ± 0.071 [0.214, 0.265] | 0.729 ± 0.305 [0.619, 0.834] |

## Per-family recall
| Family | B0 static | B1 VNSF | B2 rules | B3 net-only | EASA-C | EASA-PH | EASA |
|---|---|---|---|---|---|---|---|
| DoS | 0.00 | 0.92 | 0.11 | 0.91 | 0.91 | 0.91 | 0.87 |
| DDoS | 0.00 | 0.66 | 0.20 | 0.80 | 0.58 | 0.80 | 0.69 |
| Mirai | 0.00 | 0.68 | 0.19 | 0.65 | 0.61 | 0.64 | 0.59 |
| Recon | 0.00 | 0.77 | 0.10 | 0.86 | 0.69 | 0.87 | 0.83 |
| Spoofing | 0.00 | 0.69 | 0.09 | 0.57 | 0.56 | 0.58 | 0.52 |
| Web | 0.00 | 0.91 | 0.15 | 0.88 | 0.85 | 0.88 | 0.85 |
| FirmwareTamper | 0.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 |
| CredentialReplay | 0.00 | 0.20 | 0.27 | 0.21 | 0.20 | 0.81 | 0.74 |

## Calibrated thresholds
| Configuration | τ_L1 | τ_L2 | τ_L3 |
|---|---|---|---|
| B0 static | 0.800 ± 0.000 | 0.600 ± 0.000 | 0.350 ± 0.000 |
| B1 VNSF | 0.819 ± 0.028 | 0.537 ± 0.037 | 0.359 ± 0.042 |
| B2 rules | 0.531 ± 0.125 | 0.364 ± 0.011 | 0.227 ± 0.033 |
| B3 net-only | 0.606 ± 0.052 | 0.311 ± 0.061 | 0.197 ± 0.081 |
| EASA$-$C | 0.738 ± 0.024 | 0.557 ± 0.029 | 0.349 ± 0.079 |
| EASA$-$PH | 0.606 ± 0.052 | 0.311 ± 0.061 | 0.197 ± 0.081 |
| EASA | 0.741 ± 0.024 | 0.539 ± 0.036 | 0.349 ± 0.074 |

## Cloud calls

## Credential-replay denominators
| Configuration | runs with a revocation | campaigns with revoked donor | catch (all runs) | catch (runs with revocation) |
|---|---|---|---|---|
| B1 VNSF | 30/30 | 96% | 0.201 ± 0.215 | 0.201 $\pm$ 0.215 ($n=30$) |
| B2 rules | 9/30 | 26% | 0.272 ± 0.328 | 0.659 $\pm$ 0.263 ($n=9$) |
| B3 net-only | 26/30 | 83% | 0.213 ± 0.246 | 0.225 $\pm$ 0.256 ($n=26$) |
| EASA$-$C | 28/30 | 86% | 0.178 ± 0.240 | 0.179 $\pm$ 0.245 ($n=28$) |
| EASA$-$PH | 26/30 | 83% | 0.811 ± 0.308 | 0.916 $\pm$ 0.148 ($n=26$) |
| EASA | 26/30 | 79% | 0.729 ± 0.305 | 0.777 $\pm$ 0.263 ($n=26$) |

## Benign-side cost
| Configuration | FPR (clean devices) | Restricted share (all benign epochs) | Post-attack dwell (s / compromised device) | False quarantine |
|---|---|---|---|---|
| B0 static | 0.000 ± 0.000 | 0.000 ± 0.000 | 0 ± 0 | 0.000 ± 0.000 |
| B1 VNSF | 0.050 ± 0.026 | 0.186 ± 0.029 | 1229 ± 163 | 0.071 ± 0.031 |
| B2 rules | 0.032 ± 0.030 | 0.065 ± 0.027 | 360 ± 167 | 0.054 ± 0.046 |
| B3 net-only | 0.017 ± 0.015 | 0.163 ± 0.034 | 1210 ± 271 | 0.017 ± 0.022 |
| EASA$-$C | 0.024 ± 0.022 | 0.157 ± 0.044 | 1124 ± 292 | 0.020 ± 0.031 |
| EASA$-$PH | 0.017 ± 0.015 | 0.166 ± 0.034 | 1230 ± 266 | 0.017 ± 0.022 |
| EASA | 0.020 ± 0.018 | 0.174 ± 0.032 | 1286 ± 277 | 0.016 ± 0.022 |

## Restriction activation decomposition
| Configuration | Activated (any) | Already restricted at onset | Newly restricted | TTC p50, newly restricted (s) |
|---|---|---|---|---|
| B0 static | 0.000 ± 0.000 | 0.000 ± 0.000 | 0.000 ± 0.000 | -- |
| B1 VNSF | 0.807 ± 0.089 | 0.154 ± 0.075 | 0.653 ± 0.122 | 42 ± 17 |
| B2 rules | 0.282 ± 0.157 | 0.051 ± 0.036 | 0.231 ± 0.151 | 135 ± 135 |
| B3 net-only | 0.833 ± 0.093 | 0.131 ± 0.071 | 0.702 ± 0.087 | 48 ± 17 |
| EASA$-$C | 0.744 ± 0.120 | 0.138 ± 0.073 | 0.606 ± 0.100 | 53 ± 28 |
| EASA$-$PH | 0.926 ± 0.081 | 0.131 ± 0.072 | 0.795 ± 0.089 | 47 ± 17 |
| EASA | 0.887 ± 0.091 | 0.149 ± 0.075 | 0.738 ± 0.085 | 64 ± 25 |

## Paired differences vs EASA_full (mean, bootstrap CI, Holm p)
| Metric | Comparison | Δ (EASA − other) | 95% CI | p (Holm) | seeds EASA better |
|---|---|---|---|---|---|
| F1 ($L_2$) | B0 static | +0.764 | [0.729, 0.800] | $<0.001$ | 30/30 |
|  | B1 VNSF | +0.124 | [0.077, 0.168] | $<0.001$ | 24/30 |
|  | B2 rules | +0.507 | [0.446, 0.567] | $<0.001$ | 30/30 |
|  | B3 net-only | +0.005 | [-0.030, 0.038] | 0.761 | 16/30 |
|  | EASA$-$C | +0.090 | [0.043, 0.135] | 0.002 | 23/30 |
|  | EASA$-$PH | -0.051 | [-0.080, -0.026] | $<0.001$ | 7/30 |
| FPR | B0 static | +0.020 | [0.014, 0.027] | $<0.001$ | 0/30 |
|  | B1 VNSF | -0.030 | [-0.040, -0.020] | $<0.001$ | 26/30 |
|  | B2 rules | -0.012 | [-0.024, 0.001] | 0.486 | 16/30 |
|  | B3 net-only | +0.004 | [-0.001, 0.010] | 1.000 | 12/30 |
|  | EASA$-$C | -0.004 | [-0.013, 0.006] | 1.000 | 17/30 |
|  | EASA$-$PH | +0.004 | [-0.001, 0.010] | 1.000 | 12/30 |
| Recall (in-dist.) | B0 static | +0.762 | [0.718, 0.802] | $<0.001$ | 30/30 |
|  | B1 VNSF | -0.110 | [-0.148, -0.075] | $<0.001$ | 2/30 |
|  | B2 rules | +0.598 | [0.531, 0.661] | $<0.001$ | 30/30 |
|  | B3 net-only | -0.049 | [-0.071, -0.027] | $<0.001$ | 3/30 |
|  | EASA$-$C | -0.042 | [-0.080, -0.008] | 0.052 | 10/30 |
|  | EASA$-$PH | -0.049 | [-0.074, -0.027] | $<0.001$ | 4/30 |
| Recall (cross-site) | B0 static | +0.687 | [0.644, 0.728] | $<0.001$ | 30/30 |
|  | B1 VNSF | +0.014 | [-0.043, 0.073] | 0.792 | 14/30 |
|  | B2 rules | +0.568 | [0.503, 0.628] | $<0.001$ | 30/30 |
|  | B3 net-only | -0.076 | [-0.120, -0.035] | 0.003 | 6/30 |
|  | EASA$-$C | +0.127 | [0.057, 0.201] | 0.003 | 23/30 |
|  | EASA$-$PH | -0.078 | [-0.119, -0.039] | 0.003 | 6/30 |
| Activation | B0 static | +0.887 | [0.855, 0.918] | $<0.001$ | 30/30 |
|  | B1 VNSF | +0.081 | [0.043, 0.118] | 0.001 | 23/30 |
|  | B2 rules | +0.605 | [0.542, 0.669] | $<0.001$ | 30/30 |
|  | B3 net-only | +0.055 | [0.029, 0.081] | 0.001 | 22/30 |
|  | EASA$-$C | +0.143 | [0.107, 0.179] | $<0.001$ | 29/30 |
|  | EASA$-$PH | -0.038 | [-0.067, -0.012] | 0.014 | 7/30 |
| Replay catch (all runs) | B0 static | +0.729 | [0.616, 0.829] | $<0.001$ | 28/30 |
|  | B1 VNSF | +0.528 | [0.424, 0.632] | $<0.001$ | 28/30 |
|  | B2 rules | +0.457 | [0.275, 0.616] | $<0.001$ | 22/30 |
|  | B3 net-only | +0.516 | [0.387, 0.640] | $<0.001$ | 26/30 |
|  | EASA$-$C | +0.551 | [0.435, 0.659] | $<0.001$ | 26/30 |
|  | EASA$-$PH | -0.082 | [-0.172, 0.015] | 0.022 | 3/30 |
| Metric | Comparison | Δ (EASA − other) | 95% CI | p (Holm) | seeds EASA better |
|---|---|---|---|---|---|
| False quarantine | B0 static | +0.016 | [0.009, 0.024] | 0.009 | 0/30 |
|  | B1 VNSF | -0.055 | [-0.067, -0.044] | $<0.001$ | 28/30 |
|  | B2 rules | -0.038 | [-0.055, -0.022] | 0.002 | 17/30 |
|  | B3 net-only | -0.001 | [-0.008, 0.005] | 1.000 | 4/30 |
|  | EASA$-$C | -0.004 | [-0.017, 0.007] | 1.000 | 7/30 |
|  | EASA$-$PH | -0.001 | [-0.008, 0.005] | 1.000 | 4/30 |
| Re-auth / dev-h | B0 static | +0.240 | [0.216, 0.264] | $<0.001$ | 0/30 |
|  | B1 VNSF | +0.240 | [0.214, 0.264] | $<0.001$ | 0/30 |
|  | B2 rules | +0.240 | [0.215, 0.263] | $<0.001$ | 0/30 |
|  | B3 net-only | +0.040 | [0.005, 0.076] | 0.139 | 8/30 |
|  | EASA$-$C | -0.001 | [-0.028, 0.024] | 0.766 | 14/30 |
|  | EASA$-$PH | +0.042 | [0.009, 0.077] | 0.139 | 8/30 |
| Restricted share (all benign epochs) | B0 static | +0.174 | [0.163, 0.186] | $<0.001$ | 0/30 |
|  | B1 VNSF | -0.012 | [-0.023, -0.001] | 0.062 | 18/30 |
|  | B2 rules | +0.109 | [0.094, 0.126] | $<0.001$ | 0/30 |
|  | B3 net-only | +0.011 | [0.002, 0.019] | 0.036 | 9/30 |
|  | EASA$-$C | +0.017 | [0.004, 0.030] | 0.015 | 7/30 |
|  | EASA$-$PH | +0.008 | [0.000, 0.016] | 0.062 | 10/30 |
| Post-attack dwell (s) | B0 static | +1285.901 | [1194.239, 1381.652] | $<0.001$ | 0/30 |
|  | B1 VNSF | +56.526 | [-24.656, 140.066] | 0.176 | 11/30 |
|  | B2 rules | +925.559 | [816.961, 1041.333] | $<0.001$ | 0/30 |
|  | B3 net-only | +75.648 | [5.531, 144.359] | 0.135 | 10/30 |
|  | EASA$-$C | +162.396 | [76.563, 259.709] | 0.002 | 6/30 |
|  | EASA$-$PH | +55.417 | [-11.197, 117.646] | 0.176 | 11/30 |

## Significance (paired Wilcoxon vs EASA_full, Holm)
F1 ($L_2$): B0_static: Δ(EASA−B0_static)=+0.764 (EASA better) p_holm=0.0000 ***; B1_vnsf: Δ(EASA−B1_vnsf)=+0.124 (EASA better) p_holm=0.0001 ***; B2_rules: Δ(EASA−B2_rules)=+0.507 (EASA better) p_holm=0.0000 ***; B3_net_only: Δ(EASA−B3_net_only)=+0.005 (EASA better) p_holm=0.7611 n.s.; EASA_minus_C: Δ(EASA−EASA_minus_C)=+0.090 (EASA better) p_holm=0.0019 **; EASA_net_score: Δ(EASA−EASA_net_score)=-0.051 (EASA worse) p_holm=0.0006 ***
FPR: B0_static: Δ(EASA−B0_static)=+0.020 (EASA worse) p_holm=0.0003 ***; B1_vnsf: Δ(EASA−B1_vnsf)=-0.030 (EASA better) p_holm=0.0000 ***; B2_rules: Δ(EASA−B2_rules)=-0.012 (EASA better) p_holm=0.4860 n.s.; B3_net_only: Δ(EASA−B3_net_only)=+0.004 (EASA worse) p_holm=1.0000 n.s.; EASA_minus_C: Δ(EASA−EASA_minus_C)=-0.004 (EASA better) p_holm=1.0000 n.s.; EASA_net_score: Δ(EASA−EASA_net_score)=+0.004 (EASA worse) p_holm=1.0000 n.s.
Recall (in-dist.): B0_static: Δ(EASA−B0_static)=+0.762 (EASA better) p_holm=0.0000 ***; B1_vnsf: Δ(EASA−B1_vnsf)=-0.110 (EASA worse) p_holm=0.0000 ***; B2_rules: Δ(EASA−B2_rules)=+0.598 (EASA better) p_holm=0.0000 ***; B3_net_only: Δ(EASA−B3_net_only)=-0.049 (EASA worse) p_holm=0.0004 ***; EASA_minus_C: Δ(EASA−EASA_minus_C)=-0.042 (EASA worse) p_holm=0.0523 n.s.; EASA_net_score: Δ(EASA−EASA_net_score)=-0.049 (EASA worse) p_holm=0.0004 ***
Recall (cross-site): B0_static: Δ(EASA−B0_static)=+0.687 (EASA better) p_holm=0.0000 ***; B1_vnsf: Δ(EASA−B1_vnsf)=+0.014 (EASA better) p_holm=0.7922 n.s.; B2_rules: Δ(EASA−B2_rules)=+0.568 (EASA better) p_holm=0.0000 ***; B3_net_only: Δ(EASA−B3_net_only)=-0.076 (EASA worse) p_holm=0.0034 **; EASA_minus_C: Δ(EASA−EASA_minus_C)=+0.127 (EASA better) p_holm=0.0034 **; EASA_net_score: Δ(EASA−EASA_net_score)=-0.078 (EASA worse) p_holm=0.0027 **
Activation: B0_static: Δ(EASA−B0_static)=+0.887 (EASA better) p_holm=0.0000 ***; B1_vnsf: Δ(EASA−B1_vnsf)=+0.081 (EASA better) p_holm=0.0012 **; B2_rules: Δ(EASA−B2_rules)=+0.605 (EASA better) p_holm=0.0000 ***; B3_net_only: Δ(EASA−B3_net_only)=+0.055 (EASA better) p_holm=0.0012 **; EASA_minus_C: Δ(EASA−EASA_minus_C)=+0.143 (EASA better) p_holm=0.0000 ***; EASA_net_score: Δ(EASA−EASA_net_score)=-0.038 (EASA worse) p_holm=0.0137 *
TTC p50 (s): B1_vnsf: Δ(EASA−B1_vnsf)=+14.000 (EASA worse) p_holm=0.0036 **; B2_rules: Δ(EASA−B2_rules)=-47.241 (EASA better) p_holm=0.5468 n.s.; B3_net_only: Δ(EASA−B3_net_only)=+4.667 (EASA worse) p_holm=0.5468 n.s.; EASA_minus_C: Δ(EASA−EASA_minus_C)=+4.500 (EASA worse) p_holm=0.5468 n.s.; EASA_net_score: Δ(EASA−EASA_net_score)=+6.833 (EASA worse) p_holm=0.0763 n.s.
False quarantine: B0_static: Δ(EASA−B0_static)=+0.016 (EASA worse) p_holm=0.0088 **; B1_vnsf: Δ(EASA−B1_vnsf)=-0.055 (EASA better) p_holm=0.0000 ***; B2_rules: Δ(EASA−B2_rules)=-0.038 (EASA better) p_holm=0.0023 **; B3_net_only: Δ(EASA−B3_net_only)=-0.001 (EASA better) p_holm=1.0000 n.s.; EASA_minus_C: Δ(EASA−EASA_minus_C)=-0.004 (EASA better) p_holm=1.0000 n.s.; EASA_net_score: Δ(EASA−EASA_net_score)=-0.001 (EASA better) p_holm=1.0000 n.s.
Re-auth / dev-h: B0_static: Δ(EASA−B0_static)=+0.240 (EASA worse) p_holm=0.0000 ***; B1_vnsf: Δ(EASA−B1_vnsf)=+0.240 (EASA worse) p_holm=0.0000 ***; B2_rules: Δ(EASA−B2_rules)=+0.240 (EASA worse) p_holm=0.0000 ***; B3_net_only: Δ(EASA−B3_net_only)=+0.040 (EASA worse) p_holm=0.1386 n.s.; EASA_minus_C: Δ(EASA−EASA_minus_C)=-0.001 (EASA better) p_holm=0.7664 n.s.; EASA_net_score: Δ(EASA−EASA_net_score)=+0.042 (EASA worse) p_holm=0.1386 n.s.
Replay catch (all runs): B0_static: Δ(EASA−B0_static)=+0.729 (EASA better) p_holm=0.0000 ***; B1_vnsf: Δ(EASA−B1_vnsf)=+0.528 (EASA better) p_holm=0.0000 ***; B2_rules: Δ(EASA−B2_rules)=+0.457 (EASA better) p_holm=0.0004 ***; B3_net_only: Δ(EASA−B3_net_only)=+0.516 (EASA better) p_holm=0.0000 ***; EASA_minus_C: Δ(EASA−EASA_minus_C)=+0.551 (EASA better) p_holm=0.0000 ***; EASA_net_score: Δ(EASA−EASA_net_score)=-0.082 (EASA worse) p_holm=0.0218 *

## Sensitivity
| axis | value | F1 B3 net-only | F1 EASA | FPR B3 net-only | FPR EASA | Cross-site B3 net-only | Cross-site EASA | Activation B3 net-only | Activation EASA | Restricted share B3 net-only | Restricted share EASA | Re-auth/dev-h B3 net-only | Re-auth/dev-h EASA |
| w_net | 0.4 | 0.775 | 0.768 | 0.016 | 0.037 | 0.768 | 0.822 | 0.866 | 0.950 | 0.169 | 0.228 | 0.166 | 0.123 |
| w_net | 0.5 | 0.775 | 0.779 | 0.016 | 0.023 | 0.768 | 0.718 | 0.866 | 0.938 | 0.169 | 0.199 | 0.166 | 0.232 |
| w_net | 0.6 | 0.775 | 0.777 | 0.016 | 0.020 | 0.768 | 0.709 | 0.866 | 0.898 | 0.169 | 0.169 | 0.166 | 0.221 |
| w_net | 0.7 | 0.775 | 0.755 | 0.016 | 0.028 | 0.768 | 0.703 | 0.866 | 0.894 | 0.169 | 0.172 | 0.166 | 0.237 |
| w_net | 0.8 | 0.775 | 0.757 | 0.016 | 0.025 | 0.768 | 0.749 | 0.866 | 0.892 | 0.169 | 0.165 | 0.166 | 0.218 |
| beta | 0.5 | 0.803 | 0.789 | 0.013 | 0.021 | 0.822 | 0.701 | 0.879 | 0.897 | 0.164 | 0.170 | 0.109 | 0.212 |
| beta | 0.7 | 0.775 | 0.777 | 0.016 | 0.020 | 0.768 | 0.709 | 0.866 | 0.898 | 0.169 | 0.169 | 0.166 | 0.221 |
| beta | 0.9 | 0.684 | 0.696 | 0.015 | 0.018 | 0.577 | 0.572 | 0.818 | 0.863 | 0.174 | 0.183 | 0.230 | 0.239 |
| h | 3 | 0.775 | 0.777 | 0.016 | 0.020 | 0.768 | 0.709 | 0.866 | 0.898 | 0.168 | 0.168 | 0.166 | 0.221 |
| h | 5 | 0.775 | 0.777 | 0.016 | 0.020 | 0.768 | 0.709 | 0.866 | 0.898 | 0.169 | 0.169 | 0.166 | 0.221 |
| h | 10 | 0.775 | 0.777 | 0.016 | 0.020 | 0.770 | 0.709 | 0.866 | 0.898 | 0.170 | 0.171 | 0.164 | 0.221 |
| k | 1 | 0.629 | 0.671 | 0.027 | 0.029 | 0.584 | 0.553 | 0.722 | 0.795 | 0.130 | 0.155 | 0.279 | 0.280 |
| k | 3 | 0.775 | 0.777 | 0.016 | 0.020 | 0.768 | 0.709 | 0.866 | 0.898 | 0.169 | 0.169 | 0.166 | 0.221 |
| k | 5 | 0.769 | 0.809 | 0.013 | 0.019 | 0.765 | 0.788 | 0.846 | 0.941 | 0.156 | 0.189 | 0.146 | 0.239 |
| target_fpr | 0.01 | 0.720 | 0.772 | 0.023 | 0.017 | 0.667 | 0.677 | 0.834 | 0.860 | 0.162 | 0.167 | 0.102 | 0.207 |
| target_fpr | 0.02 | 0.775 | 0.777 | 0.016 | 0.020 | 0.768 | 0.709 | 0.866 | 0.898 | 0.169 | 0.169 | 0.166 | 0.221 |
| target_fpr | 0.05 | 0.720 | 0.707 | 0.039 | 0.051 | 0.810 | 0.763 | 0.887 | 0.945 | 0.177 | 0.202 | 0.284 | 0.307 |

## Low-battery scenario
| Configuration | Deferred, cancelled | Deferred, pending at end | Re-auth / dev-h | Residual energy | F1 | FPR (clean) | Activation | Dwell (s) |
|---|---|---|---|---|---|---|---|---|
| B3 net-only | 0.00 | 0.00 | 0.200 ± 0.099 | 0.364 ± 0.043 | 0.759 ± 0.101 | 0.017 ± 0.015 | 0.833 ± 0.093 | 1210 ± 271 |
| EASA, no energy-aware action | 0.00 | 0.00 | 0.251 ± 0.052 | 0.365 ± 0.045 | 0.736 ± 0.106 | 0.024 ± 0.020 | 0.874 ± 0.101 | 1260 ± 289 |
| EASA | 0.77 ± 1.22 | 5.63 ± 1.97 | 0.137 ± 0.055 | 0.365 ± 0.045 | 0.736 ± 0.106 | 0.024 ± 0.020 | 0.874 ± 0.101 | 1260 ± 289 |

## Supplementary: history reset
| Metric | EASA | EASA, history reset | Δ (reset − EASA) | 95% CI | p (unadjusted) |
|---|---|---|---|---|---|
| F1 | 0.764 | 0.766 | +0.002 | [-0.010, 0.011] | 0.152 |
| FPR (clean) | 0.020 | 0.021 | +0.000 | [-0.001, 0.003] | 0.508 |
| Restricted share | 0.174 | 0.167 | -0.007 | [-0.010, -0.005] | $<0.001$ |
| Dwell (s) | 1285.901 | 1223.584 | -62.317 | [-85.750, -41.144] | $<0.001$ |
| False quarantine | 0.016 | 0.017 | +0.001 | [0.000, 0.003] | 0.317 |
| Activation | 0.887 | 0.892 | +0.004 | [-0.004, 0.014] | 0.273 |
| Cross-site recall | 0.687 | 0.704 | +0.017 | [-0.002, 0.041] | 0.116 |
| Replay catch | 0.729 | 0.730 | +0.001 | [0.000, 0.004] | 0.317 |
| Re-auth / dev-h | 0.240 | 0.245 | +0.005 | [-0.001, 0.014] | 0.197 |
