# Results summary
source: ../results_v3/final_main_v3.csv, 210 runs, 30 seeds

## Main table
| Configuration | F1 ($L_2$) | FPR | Recall (in-dist.) | Recall (cross-site) | Containment | TTC p50 (s) | False quarantine | Re-auth / dev-h | Replay catch (all runs) |
|---|---|---|---|---|---|---|---|---|---|
| B0 static | 0.000 ± 0.000 [0.000, 0.000] | 0.000 ± 0.000 [0.000, 0.000] | 0.000 ± 0.000 [0.000, 0.000] | 0.000 ± 0.000 [0.000, 0.000] | 0.000 ± 0.000 [0.000, 0.000] | -- | 0.000 ± 0.000 [0.000, 0.000] | 0.000 ± 0.000 [0.000, 0.000] | 0.000 ± 0.000 [0.000, 0.000] |
| B1 VNSF | 0.497 ± 0.106 [0.460, 0.535] | 0.053 ± 0.023 [0.045, 0.061] | 0.821 ± 0.110 [0.778, 0.854] | 0.346 ± 0.178 [0.283, 0.408] | 0.681 ± 0.148 [0.627, 0.728] | 42 ± 19 [35, 48] | 0.077 ± 0.032 [0.066, 0.088] | 0.000 ± 0.000 [0.000, 0.000] | 0.182 ± 0.229 [0.106, 0.270] |
| B2 rules | 0.216 ± 0.123 [0.171, 0.261] | 0.047 ± 0.029 [0.037, 0.057] | 0.144 ± 0.138 [0.098, 0.194] | 0.138 ± 0.138 [0.093, 0.189] | 0.265 ± 0.164 [0.210, 0.325] | 61 ± 79 [33, 89] | 0.077 ± 0.042 [0.062, 0.092] | 0.000 ± 0.000 [0.000, 0.000] | 0.165 ± 0.256 [0.085, 0.262] |
| B3 net-only | 0.564 ± 0.108 [0.525, 0.603] | 0.050 ± 0.024 [0.041, 0.058] | 0.772 ± 0.114 [0.731, 0.810] | 0.627 ± 0.217 [0.555, 0.701] | 0.763 ± 0.095 [0.729, 0.794] | 35 ± 17 [30, 41] | 0.026 ± 0.017 [0.020, 0.033] | 0.247 ± 0.057 [0.227, 0.267] | 0.138 ± 0.170 [0.082, 0.204] |
| EASA-C | 0.439 ± 0.089 [0.408, 0.472] | 0.048 ± 0.027 [0.039, 0.058] | 0.675 ± 0.142 [0.621, 0.720] | 0.237 ± 0.165 [0.183, 0.294] | 0.555 ± 0.134 [0.505, 0.601] | 58 ± 34 [47, 70] | 0.024 ± 0.019 [0.017, 0.031] | 0.195 ± 0.065 [0.173, 0.219] | 0.122 ± 0.168 [0.064, 0.184] |
| EASA-PH | 0.615 ± 0.102 [0.579, 0.651] | 0.050 ± 0.024 [0.042, 0.059] | 0.772 ± 0.114 [0.731, 0.810] | 0.630 ± 0.214 [0.553, 0.703] | 0.849 ± 0.099 [0.812, 0.882] | 33 ± 20 [26, 40] | 0.026 ± 0.017 [0.020, 0.033] | 0.246 ± 0.057 [0.226, 0.266] | 0.757 ± 0.295 [0.652, 0.854] |
| EASA | 0.601 ± 0.098 [0.565, 0.634] | 0.054 ± 0.023 [0.046, 0.062] | 0.756 ± 0.117 [0.714, 0.795] | 0.599 ± 0.172 [0.539, 0.660] | 0.849 ± 0.127 [0.803, 0.891] | 38 ± 24 [30, 47] | 0.042 ± 0.029 [0.032, 0.052] | 0.228 ± 0.047 [0.212, 0.245] | 0.806 ± 0.283 [0.698, 0.898] |

## Per-family recall
| Family | B0 static | B1 VNSF | B2 rules | B3 net-only | EASA-C | EASA-PH | EASA |
|---|---|---|---|---|---|---|---|
| DoS | 0.00 | 0.90 | 0.14 | 0.93 | 0.87 | 0.93 | 0.92 |
| DDoS | 0.00 | 0.43 | 0.14 | 0.80 | 0.37 | 0.80 | 0.77 |
| Mirai | 0.00 | 0.72 | 0.21 | 0.69 | 0.49 | 0.69 | 0.70 |
| Recon | 0.00 | 0.49 | 0.10 | 0.73 | 0.29 | 0.73 | 0.67 |
| Spoofing | 0.00 | 0.41 | 0.13 | 0.40 | 0.31 | 0.40 | 0.43 |
| Web | 0.00 | 0.80 | 0.14 | 0.82 | 0.62 | 0.82 | 0.70 |
| FirmwareTamper | 0.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 |
| CredentialReplay | 0.00 | 0.18 | 0.16 | 0.15 | 0.19 | 0.76 | 0.82 |

## Calibrated thresholds
| Configuration | τ_L1 | τ_L2 | τ_L3 |
|---|---|---|---|
| B0 static | 0.800 ± 0.000 | 0.600 ± 0.000 | 0.350 ± 0.000 |
| B1 VNSF | 0.789 ± 0.028 | 0.519 ± 0.038 | 0.224 ± 0.055 |
| B2 rules | 0.505 ± 0.114 | 0.362 ± 0.009 | 0.172 ± 0.082 |
| B3 net-only | 0.626 ± 0.035 | 0.461 ± 0.051 | 0.251 ± 0.083 |
| EASA$-$C | 0.733 ± 0.015 | 0.553 ± 0.059 | 0.286 ± 0.061 |
| EASA$-$PH | 0.626 ± 0.035 | 0.461 ± 0.051 | 0.251 ± 0.083 |
| EASA | 0.743 ± 0.021 | 0.625 ± 0.029 | 0.414 ± 0.069 |

## Cloud calls
| Configuration | Calls / run | RTT p50 (ms) | RTT p95 (ms) | RTT max (ms) | Retried | Dropped |
|---|---|---|---|---|---|---|
| B2 rules | 369 | 102 | 106 | 631 | 0 | 0 |
| B3 net-only | 127 | 122 | 159 | 391 | 0 | 0 |
| EASA$-$PH | 611 | 102 | 124 | 397 | 0 | 0 |
| EASA | 596 | 103 | 124 | 1257 | 0 | 0 |

## Credential-replay denominators
| Configuration | runs with a revocation | campaigns with revoked donor | catch (all runs) | catch (runs with revocation) |
|---|---|---|---|---|
| B1 VNSF | 30/30 | 93% | 0.182 ± 0.229 | 0.182 $\pm$ 0.229 ($n=30$) |
| B2 rules | 5/30 | 14% | 0.165 ± 0.256 | 0.661 $\pm$ 0.104 ($n=5$) |
| B3 net-only | 26/30 | 78% | 0.138 ± 0.170 | 0.111 $\pm$ 0.143 ($n=26$) |
| EASA$-$C | 21/30 | 66% | 0.122 ± 0.168 | 0.099 $\pm$ 0.137 ($n=21$) |
| EASA$-$PH | 26/30 | 78% | 0.757 ± 0.295 | 0.825 $\pm$ 0.240 ($n=26$) |
| EASA | 28/30 | 89% | 0.806 ± 0.283 | 0.852 $\pm$ 0.227 ($n=28$) |

## Benign-side cost
| Configuration | FPR (clean devices) | Restricted share (all benign epochs) | Post-attack dwell (s / compromised device) | False quarantine |
|---|---|---|---|---|
| B0 static | 0.000 ± 0.000 | 0.000 ± 0.000 | 0 ± 0 | 0.000 ± 0.000 |
| B1 VNSF | 0.053 ± 0.023 | 0.145 ± 0.035 | 975 ± 255 | 0.077 ± 0.032 |
| B2 rules | 0.047 ± 0.029 | 0.070 ± 0.027 | 355 ± 234 | 0.077 ± 0.042 |
| B3 net-only | 0.050 ± 0.024 | 0.140 ± 0.023 | 950 ± 184 | 0.026 ± 0.017 |
| EASA$-$C | 0.048 ± 0.027 | 0.119 ± 0.037 | 782 ± 245 | 0.024 ± 0.019 |
| EASA$-$PH | 0.050 ± 0.024 | 0.141 ± 0.024 | 962 ± 183 | 0.026 ± 0.017 |
| EASA | 0.054 ± 0.023 | 0.175 ± 0.037 | 1236 ± 308 | 0.042 ± 0.029 |

## Restriction activation decomposition
| Configuration | Activated (any) | Already restricted at onset | Newly restricted | TTC p50, newly restricted (s) |
|---|---|---|---|---|
| B0 static | 0.000 ± 0.000 | 0.000 ± 0.000 | 0.000 ± 0.000 | -- |
| B1 VNSF | 0.681 ± 0.148 | 0.099 ± 0.066 | 0.583 ± 0.132 | 53 ± 16 |
| B2 rules | 0.265 ± 0.164 | 0.058 ± 0.055 | 0.207 ± 0.138 | 114 ± 115 |
| B3 net-only | 0.763 ± 0.095 | 0.108 ± 0.064 | 0.655 ± 0.091 | 47 ± 22 |
| EASA$-$C | 0.555 ± 0.134 | 0.090 ± 0.056 | 0.466 ± 0.118 | 74 ± 40 |
| EASA$-$PH | 0.849 ± 0.099 | 0.107 ± 0.064 | 0.742 ± 0.111 | 42 ± 23 |
| EASA | 0.849 ± 0.127 | 0.129 ± 0.059 | 0.720 ± 0.120 | 52 ± 29 |

## Paired differences vs EASA_full (mean, bootstrap CI, Holm p)
| Metric | Comparison | Δ (EASA − other) | 95% CI | p (Holm) | seeds EASA better |
|---|---|---|---|---|---|
| F1 ($L_2$) | B0 static | +0.601 | [0.567, 0.634] | $<0.001$ | 30/30 |
|  | B1 VNSF | +0.103 | [0.056, 0.155] | $<0.001$ | 27/30 |
|  | B2 rules | +0.385 | [0.325, 0.439] | $<0.001$ | 29/30 |
|  | B3 net-only | +0.037 | [-0.001, 0.073] | 0.090 | 21/30 |
|  | EASA$-$C | +0.162 | [0.122, 0.206] | $<0.001$ | 26/30 |
|  | EASA$-$PH | -0.014 | [-0.053, 0.022] | 0.777 | 17/30 |
| FPR | B0 static | +0.054 | [0.045, 0.062] | $<0.001$ | 0/30 |
|  | B1 VNSF | +0.001 | [-0.009, 0.010] | 1.000 | 14/30 |
|  | B2 rules | +0.007 | [-0.003, 0.016] | 1.000 | 9/30 |
|  | B3 net-only | +0.004 | [-0.004, 0.011] | 1.000 | 13/30 |
|  | EASA$-$C | +0.005 | [-0.003, 0.014] | 1.000 | 11/30 |
|  | EASA$-$PH | +0.004 | [-0.003, 0.011] | 1.000 | 13/30 |
| Recall (in-dist.) | B0 static | +0.756 | [0.715, 0.794] | $<0.001$ | 30/30 |
|  | B1 VNSF | -0.065 | [-0.119, -0.007] | 0.088 | 9/30 |
|  | B2 rules | +0.612 | [0.534, 0.681] | $<0.001$ | 29/30 |
|  | B3 net-only | -0.016 | [-0.061, 0.028] | 1.000 | 13/30 |
|  | EASA$-$C | +0.081 | [0.018, 0.146] | 0.089 | 20/30 |
|  | EASA$-$PH | -0.016 | [-0.059, 0.028] | 1.000 | 13/30 |
| Recall (cross-site) | B0 static | +0.599 | [0.540, 0.658] | $<0.001$ | 30/30 |
|  | B1 VNSF | +0.253 | [0.162, 0.348] | $<0.001$ | 26/30 |
|  | B2 rules | +0.461 | [0.394, 0.530] | $<0.001$ | 30/30 |
|  | B3 net-only | -0.028 | [-0.114, 0.055] | 0.980 | 13/30 |
|  | EASA$-$C | +0.362 | [0.276, 0.449] | $<0.001$ | 29/30 |
|  | EASA$-$PH | -0.031 | [-0.110, 0.056] | 0.980 | 13/30 |
| Containment | B0 static | +0.849 | [0.801, 0.891] | $<0.001$ | 30/30 |
|  | B1 VNSF | +0.167 | [0.100, 0.239] | $<0.001$ | 23/30 |
|  | B2 rules | +0.584 | [0.498, 0.658] | $<0.001$ | 29/30 |
|  | B3 net-only | +0.085 | [0.037, 0.134] | 0.010 | 22/30 |
|  | EASA$-$C | +0.293 | [0.220, 0.368] | $<0.001$ | 28/30 |
|  | EASA$-$PH | -0.000 | [-0.054, 0.048] | 0.666 | 14/30 |
| Replay catch (all runs) | B0 static | +0.806 | [0.700, 0.898] | $<0.001$ | 29/30 |
|  | B1 VNSF | +0.624 | [0.484, 0.742] | $<0.001$ | 28/30 |
|  | B2 rules | +0.642 | [0.477, 0.782] | $<0.001$ | 26/30 |
|  | B3 net-only | +0.668 | [0.539, 0.786] | $<0.001$ | 28/30 |
|  | EASA$-$C | +0.684 | [0.552, 0.795] | $<0.001$ | 28/30 |
|  | EASA$-$PH | +0.049 | [-0.070, 0.172] | 0.355 | 10/30 |
| Metric | Comparison | Δ (EASA − other) | 95% CI | p (Holm) | seeds EASA better |
|---|---|---|---|---|---|
| False quarantine | B0 static | +0.042 | [0.033, 0.052] | $<0.001$ | 0/30 |
|  | B1 VNSF | -0.034 | [-0.050, -0.020] | $<0.001$ | 21/30 |
|  | B2 rules | -0.035 | [-0.051, -0.019] | 0.002 | 19/30 |
|  | B3 net-only | +0.016 | [0.006, 0.026] | 0.018 | 3/30 |
|  | EASA$-$C | +0.018 | [0.008, 0.030] | 0.018 | 3/30 |
|  | EASA$-$PH | +0.016 | [0.006, 0.027] | 0.018 | 3/30 |
| Re-auth / dev-h | B0 static | +0.228 | [0.213, 0.246] | $<0.001$ | 0/30 |
|  | B1 VNSF | +0.228 | [0.212, 0.245] | $<0.001$ | 0/30 |
|  | B2 rules | +0.228 | [0.212, 0.244] | $<0.001$ | 0/30 |
|  | B3 net-only | -0.018 | [-0.036, -0.001] | 0.134 | 17/30 |
|  | EASA$-$C | +0.033 | [0.009, 0.058] | 0.052 | 9/30 |
|  | EASA$-$PH | -0.018 | [-0.036, -0.002] | 0.134 | 16/30 |
| Restricted share (all benign epochs) | B0 static | +0.175 | [0.162, 0.188] | $<0.001$ | 0/30 |
|  | B1 VNSF | +0.030 | [0.014, 0.046] | 0.003 | 9/30 |
|  | B2 rules | +0.105 | [0.090, 0.119] | $<0.001$ | 0/30 |
|  | B3 net-only | +0.035 | [0.024, 0.046] | $<0.001$ | 5/30 |
|  | EASA$-$C | +0.055 | [0.039, 0.073] | $<0.001$ | 4/30 |
|  | EASA$-$PH | +0.034 | [0.023, 0.045] | $<0.001$ | 5/30 |
| Post-attack dwell (s) | B0 static | +1235.804 | [1133.842, 1342.995] | $<0.001$ | 0/30 |
|  | B1 VNSF | +260.332 | [149.431, 388.578] | $<0.001$ | 7/30 |
|  | B2 rules | +880.436 | [774.713, 989.298] | $<0.001$ | 0/30 |
|  | B3 net-only | +285.395 | [205.450, 370.016] | $<0.001$ | 5/30 |
|  | EASA$-$C | +454.265 | [330.030, 596.261] | $<0.001$ | 3/30 |
|  | EASA$-$PH | +273.765 | [193.215, 358.537] | $<0.001$ | 5/30 |

## Significance (paired Wilcoxon vs EASA_full, Holm)
F1 ($L_2$): B0_static: Δ(EASA−B0_static)=+0.601 (EASA better) p_holm=0.0000 ***; B1_vnsf: Δ(EASA−B1_vnsf)=+0.103 (EASA better) p_holm=0.0005 ***; B2_rules: Δ(EASA−B2_rules)=+0.385 (EASA better) p_holm=0.0000 ***; B3_net_only: Δ(EASA−B3_net_only)=+0.037 (EASA better) p_holm=0.0898 n.s.; EASA_minus_C: Δ(EASA−EASA_minus_C)=+0.162 (EASA better) p_holm=0.0000 ***; EASA_net_score: Δ(EASA−EASA_net_score)=-0.014 (EASA worse) p_holm=0.7766 n.s.
FPR: B0_static: Δ(EASA−B0_static)=+0.054 (EASA worse) p_holm=0.0000 ***; B1_vnsf: Δ(EASA−B1_vnsf)=+0.001 (EASA worse) p_holm=1.0000 n.s.; B2_rules: Δ(EASA−B2_rules)=+0.007 (EASA worse) p_holm=1.0000 n.s.; B3_net_only: Δ(EASA−B3_net_only)=+0.004 (EASA worse) p_holm=1.0000 n.s.; EASA_minus_C: Δ(EASA−EASA_minus_C)=+0.005 (EASA worse) p_holm=1.0000 n.s.; EASA_net_score: Δ(EASA−EASA_net_score)=+0.004 (EASA worse) p_holm=1.0000 n.s.
Recall (in-dist.): B0_static: Δ(EASA−B0_static)=+0.756 (EASA better) p_holm=0.0000 ***; B1_vnsf: Δ(EASA−B1_vnsf)=-0.065 (EASA worse) p_holm=0.0884 n.s.; B2_rules: Δ(EASA−B2_rules)=+0.612 (EASA better) p_holm=0.0000 ***; B3_net_only: Δ(EASA−B3_net_only)=-0.016 (EASA worse) p_holm=1.0000 n.s.; EASA_minus_C: Δ(EASA−EASA_minus_C)=+0.081 (EASA better) p_holm=0.0893 n.s.; EASA_net_score: Δ(EASA−EASA_net_score)=-0.016 (EASA worse) p_holm=1.0000 n.s.
Recall (cross-site): B0_static: Δ(EASA−B0_static)=+0.599 (EASA better) p_holm=0.0000 ***; B1_vnsf: Δ(EASA−B1_vnsf)=+0.253 (EASA better) p_holm=0.0001 ***; B2_rules: Δ(EASA−B2_rules)=+0.461 (EASA better) p_holm=0.0000 ***; B3_net_only: Δ(EASA−B3_net_only)=-0.028 (EASA worse) p_holm=0.9797 n.s.; EASA_minus_C: Δ(EASA−EASA_minus_C)=+0.362 (EASA better) p_holm=0.0000 ***; EASA_net_score: Δ(EASA−EASA_net_score)=-0.031 (EASA worse) p_holm=0.9797 n.s.
Containment: B0_static: Δ(EASA−B0_static)=+0.849 (EASA better) p_holm=0.0000 ***; B1_vnsf: Δ(EASA−B1_vnsf)=+0.167 (EASA better) p_holm=0.0007 ***; B2_rules: Δ(EASA−B2_rules)=+0.584 (EASA better) p_holm=0.0000 ***; B3_net_only: Δ(EASA−B3_net_only)=+0.085 (EASA better) p_holm=0.0095 **; EASA_minus_C: Δ(EASA−EASA_minus_C)=+0.293 (EASA better) p_holm=0.0000 ***; EASA_net_score: Δ(EASA−EASA_net_score)=-0.000 (EASA worse) p_holm=0.6658 n.s.
TTC p50 (s): B1_vnsf: Δ(EASA−B1_vnsf)=-3.833 (EASA better) p_holm=0.4089 n.s.; B2_rules: Δ(EASA−B2_rules)=-22.586 (EASA better) p_holm=1.0000 n.s.; B3_net_only: Δ(EASA−B3_net_only)=+2.667 (EASA worse) p_holm=1.0000 n.s.; EASA_minus_C: Δ(EASA−EASA_minus_C)=-20.333 (EASA better) p_holm=0.0065 **; EASA_net_score: Δ(EASA−EASA_net_score)=+4.833 (EASA worse) p_holm=1.0000 n.s.
False quarantine: B0_static: Δ(EASA−B0_static)=+0.042 (EASA worse) p_holm=0.0000 ***; B1_vnsf: Δ(EASA−B1_vnsf)=-0.034 (EASA better) p_holm=0.0010 ***; B2_rules: Δ(EASA−B2_rules)=-0.035 (EASA better) p_holm=0.0020 **; B3_net_only: Δ(EASA−B3_net_only)=+0.016 (EASA worse) p_holm=0.0179 *; EASA_minus_C: Δ(EASA−EASA_minus_C)=+0.018 (EASA worse) p_holm=0.0179 *; EASA_net_score: Δ(EASA−EASA_net_score)=+0.016 (EASA worse) p_holm=0.0179 *
Re-auth / dev-h: B0_static: Δ(EASA−B0_static)=+0.228 (EASA worse) p_holm=0.0000 ***; B1_vnsf: Δ(EASA−B1_vnsf)=+0.228 (EASA worse) p_holm=0.0000 ***; B2_rules: Δ(EASA−B2_rules)=+0.228 (EASA worse) p_holm=0.0000 ***; B3_net_only: Δ(EASA−B3_net_only)=-0.018 (EASA better) p_holm=0.1343 n.s.; EASA_minus_C: Δ(EASA−EASA_minus_C)=+0.033 (EASA worse) p_holm=0.0518 n.s.; EASA_net_score: Δ(EASA−EASA_net_score)=-0.018 (EASA better) p_holm=0.1343 n.s.
Replay catch (all runs): B0_static: Δ(EASA−B0_static)=+0.806 (EASA better) p_holm=0.0000 ***; B1_vnsf: Δ(EASA−B1_vnsf)=+0.624 (EASA better) p_holm=0.0000 ***; B2_rules: Δ(EASA−B2_rules)=+0.642 (EASA better) p_holm=0.0000 ***; B3_net_only: Δ(EASA−B3_net_only)=+0.668 (EASA better) p_holm=0.0000 ***; EASA_minus_C: Δ(EASA−EASA_minus_C)=+0.684 (EASA better) p_holm=0.0000 ***; EASA_net_score: Δ(EASA−EASA_net_score)=+0.049 (EASA better) p_holm=0.3547 n.s.

## Sensitivity
| axis | value | F1 B3 net-only | F1 EASA | FPR B3 net-only | FPR EASA | Cross-site B3 net-only | Cross-site EASA | Contain. B3 net-only | Contain. EASA | Restricted share B3 net-only | Restricted share EASA | Re-auth/dev-h B3 net-only | Re-auth/dev-h EASA |
| w_net | 0.4 | 0.535 | 0.611 | 0.063 | 0.047 | 0.591 | 0.567 | 0.772 | 0.821 | 0.150 | 0.186 | 0.258 | 0.214 |
| w_net | 0.5 | 0.535 | 0.551 | 0.063 | 0.072 | 0.591 | 0.596 | 0.772 | 0.822 | 0.150 | 0.192 | 0.258 | 0.220 |
| w_net | 0.6 | 0.535 | 0.568 | 0.063 | 0.062 | 0.591 | 0.541 | 0.772 | 0.834 | 0.150 | 0.177 | 0.258 | 0.257 |
| w_net | 0.7 | 0.535 | 0.571 | 0.063 | 0.063 | 0.591 | 0.689 | 0.772 | 0.832 | 0.150 | 0.165 | 0.258 | 0.235 |
| w_net | 0.8 | 0.535 | 0.604 | 0.063 | 0.055 | 0.591 | 0.660 | 0.772 | 0.846 | 0.150 | 0.160 | 0.258 | 0.238 |
| beta | 0.5 | 0.597 | 0.547 | 0.050 | 0.068 | 0.709 | 0.590 | 0.767 | 0.795 | 0.139 | 0.166 | 0.209 | 0.229 |
| beta | 0.7 | 0.535 | 0.568 | 0.063 | 0.062 | 0.591 | 0.541 | 0.772 | 0.834 | 0.150 | 0.177 | 0.258 | 0.257 |
| beta | 0.9 | 0.477 | 0.507 | 0.058 | 0.064 | 0.517 | 0.494 | 0.737 | 0.809 | 0.148 | 0.180 | 0.238 | 0.238 |
| h | 3 | 0.532 | 0.568 | 0.063 | 0.062 | 0.587 | 0.536 | 0.768 | 0.837 | 0.149 | 0.176 | 0.266 | 0.255 |
| h | 5 | 0.535 | 0.568 | 0.063 | 0.062 | 0.591 | 0.541 | 0.772 | 0.834 | 0.150 | 0.177 | 0.258 | 0.257 |
| h | 10 | 0.529 | 0.568 | 0.064 | 0.064 | 0.587 | 0.556 | 0.772 | 0.838 | 0.153 | 0.180 | 0.252 | 0.257 |
| k | 1 | 0.531 | 0.567 | 0.029 | 0.039 | 0.429 | 0.503 | 0.606 | 0.717 | 0.094 | 0.135 | 0.277 | 0.238 |
| k | 3 | 0.535 | 0.568 | 0.063 | 0.062 | 0.591 | 0.541 | 0.772 | 0.834 | 0.150 | 0.177 | 0.258 | 0.257 |
| k | 5 | 0.515 | 0.574 | 0.062 | 0.058 | 0.598 | 0.639 | 0.708 | 0.825 | 0.140 | 0.164 | 0.206 | 0.217 |
| target_fpr | 0.01 | 0.585 | 0.606 | 0.022 | 0.019 | 0.505 | 0.387 | 0.630 | 0.682 | 0.092 | 0.115 | 0.214 | 0.171 |
| target_fpr | 0.02 | 0.535 | 0.568 | 0.063 | 0.062 | 0.591 | 0.541 | 0.772 | 0.834 | 0.150 | 0.177 | 0.258 | 0.257 |
| target_fpr | 0.05 | 0.516 | 0.513 | 0.078 | 0.100 | 0.659 | 0.700 | 0.811 | 0.903 | 0.162 | 0.206 | 0.366 | 0.305 |

## Low-battery scenario
| Configuration | Deferred, cancelled | Deferred, pending at end | Re-auth / dev-h | Residual energy | F1 | FPR (clean) | Containment | Dwell (s) |
|---|---|---|---|---|---|---|---|---|
| B3 net-only | 0.00 | 0.00 | 0.247 ± 0.057 | 0.362 ± 0.046 | 0.564 ± 0.108 | 0.050 ± 0.024 | 0.763 ± 0.095 | 950 ± 184 |
| EASA, no energy-aware action | 0.00 | 0.00 | 0.217 ± 0.056 | 0.365 ± 0.044 | 0.605 ± 0.090 | 0.050 ± 0.025 | 0.833 ± 0.117 | 1162 ± 204 |
| EASA | 0.47 ± 0.68 | 4.80 ± 1.88 | 0.136 ± 0.044 | 0.365 ± 0.044 | 0.602 ± 0.093 | 0.051 ± 0.025 | 0.833 ± 0.117 | 1158 ± 200 |

## Supplementary: history reset
| Metric | EASA | EASA, history reset | Δ (reset − EASA) | 95% CI | p (unadjusted) |
|---|---|---|---|---|---|
| F1 | 0.601 | 0.600 | -0.001 | [-0.015, 0.012] | 0.913 |
| FPR (clean) | 0.054 | 0.053 | -0.000 | [-0.004, 0.004] | 0.173 |
| Restricted share | 0.175 | 0.166 | -0.009 | [-0.014, -0.004] | $<0.001$ |
| Dwell (s) | 1235.804 | 1162.361 | -73.443 | [-120.788, -35.966] | $<0.001$ |
| False quarantine | 0.042 | 0.045 | +0.002 | [0.000, 0.006] | 0.102 |
| Containment | 0.849 | 0.850 | +0.001 | [-0.019, 0.020] | 0.646 |
| Cross-site recall | 0.599 | 0.618 | +0.019 | [-0.008, 0.047] | 0.241 |
| Replay catch | 0.806 | 0.801 | -0.005 | [-0.054, 0.040] | 0.917 |
| Re-auth / dev-h | 0.228 | 0.235 | +0.007 | [-0.001, 0.016] | 0.075 |
