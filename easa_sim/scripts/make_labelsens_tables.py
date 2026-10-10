#!/usr/bin/env python3
"""LaTeX table of the label-rule sensitivity on the working data (Appendix E).

  python scripts/make_labelsens_tables.py results/label_sensitivity_working.csv --out figures/tab_labelsens_working.tex
"""
import argparse

import numpy as np
import pandas as pd

NAME = {"DDoS ACK Fragmentation": "DDoS ACK fragmentation", "DDoS ICMP Flood": "DDoS ICMP flood", "DDoS-HTTP Flood": "DDoS HTTP flood",
        "DDoS-ICMP_Fragmentation": "DDoS ICMP fragmentation", "DoS SYN Flood": "DoS SYN flood", "DoS-HTTP_Flood": "DoS HTTP flood",
        "DoS-UDP_Flood": "DoS UDP flood", "Mirai": "Mirai", "VulnerabilityScan": "Vulnerability scan", "DNS Spoofing": "DNS spoofing",
        "sqlinjection": "SQL injection"}
FAMILY = {"DDoS ACK Fragmentation": "DDoS", "DDoS ICMP Flood": "DDoS", "DDoS-HTTP Flood": "DDoS", "DDoS-ICMP_Fragmentation": "DDoS",
          "DoS SYN Flood": "DoS", "DoS-HTTP_Flood": "DoS", "DoS-UDP_Flood": "DoS", "Mirai": "Mirai", "VulnerabilityScan": "Recon",
          "DNS Spoofing": "Spoofing", "sqlinjection": "Web"}
SETTINGS = [(0.03, 8, "3\\%, 8"), (0.05, 6, "5\\%, 6"), (0.05, 12, "5\\%, 12"), (0.10, 8, "10\\%, 8")]


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("csv"); ap.add_argument("--out", default="figures/tab_labelsens_working.tex")
    a = ap.parse_args()
    d = pd.read_csv(a.csv); d = d[d["in_pool"] == True].drop_duplicates(["min_share", "max_attackers", "attack"])
    d["family"] = d["attack"].map(FAMILY).fillna(d["family"])
    rows = []
    for t in NAME:
        g = d[d["attack"] == t]
        if g.empty: continue
        base = g.iloc[0]
        cells = [NAME[t], f"{int(base['working_rows']):,}", f"{int(base['trace_rows']):,}" if base["trace_rows"] > 0 else "--"]
        for ms, ma, _ in SETTINGS:
            r = g[(g["min_share"] == ms) & (g["max_attackers"] == ma)]
            if r.empty: cells += ["--", "--"]; continue
            r = r.iloc[0]
            cells.append(f"{100 * r['changed_frac_all']:.1f}")
            cells.append(f"{100 * r['trace_rows_losing_attack_label_frac']:.1f}" if r["trace_rows"] > 0 else "--")
        rows.append(" & ".join(cells) + r" \\")
    # aggregate row (row-weighted over retained types; trace loss weighted by trace rows)
    agg = ["\\textbf{All retained types}", f"{int(d.drop_duplicates('attack')['working_rows'].sum()):,}", f"{int(d.drop_duplicates('attack')['trace_rows'].sum()):,}"]
    for ms, ma, _ in SETTINGS:
        g = d[(d["min_share"] == ms) & (d["max_attackers"] == ma)]
        agg.append(f"{100 * np.average(g['changed_frac_all'], weights=g['working_rows']):.1f}")
        agg.append(f"{100 * np.average(g['trace_rows_losing_attack_label_frac'].fillna(0), weights=g['trace_rows'].clip(lower=1)):.1f}")
    rows.append(r"\midrule"); rows.append(" & ".join(agg) + r" \\")
    head = " & ".join(f"\\multicolumn{{2}}{{c}}{{{lab}}}" for _, _, lab in SETTINGS)
    tex = (r"""\begin{table}[!t]
\caption{Label-rule sensitivity on the working data (script \texttt{scripts/label\_sensitivity\_working.py}): for each retained attack type, the number of working rows (train, validation and test) and of records in its replayed designated-attacker traces, and for four alternative settings of (minimum share, attacker cap) the share of working rows whose label changes (``rows'') and the share of replayed attacker-trace records that would lose the attack label (``traces''). The default is (5\%, 8); the weakness threshold does not change attacker sets. The benign device traces come from the benign capture chain only and are unaffected by every setting.}
\label{tab:labelsens-working}
\centering\scriptsize
\setlength{\tabcolsep}{3pt}
\widebox{\begin{tabular}{lrrrrrrrrrr}
\toprule
 & & & """ + head + r""" \\
\cmidrule(lr){4-5}\cmidrule(lr){6-7}\cmidrule(lr){8-9}\cmidrule(lr){10-11}
Attack type & Rows & Trace rec. & rows \% & traces \% & rows \% & traces \% & rows \% & traces \% & rows \% & traces \% \\
\midrule
""" + "\n".join(rows) + r"""
\bottomrule
\end{tabular}}
\end{table}
""")
    open(a.out, "w").write(tex); print(tex)
    for ms, ma, lab in SETTINGS:
        g = d[(d["min_share"] == ms) & (d["max_attackers"] == ma)]
        print(lab, "rows all %.1f train %.1f test %.1f | traces %.1f | max type %.1f (%s)" % (
            100 * np.average(g["changed_frac_all"], weights=g["working_rows"]), 100 * np.average(g["changed_frac_train"].fillna(0), weights=g["rows_train"]),
            100 * np.average(g["changed_frac_test"].fillna(0), weights=g["rows_test"]),
            100 * np.average(g["trace_rows_losing_attack_label_frac"].fillna(0), weights=g["trace_rows"].clip(lower=1)),
            100 * g["changed_frac_all"].max(), g.loc[g["changed_frac_all"].idxmax(), "attack"]))
        fam = g.groupby("family").apply(lambda x: 100 * np.average(x["trace_rows_losing_attack_label_frac"].fillna(0), weights=x["trace_rows"].clip(lower=1)))
        print("   trace loss by family:", fam.round(1).to_dict())


if __name__ == "__main__":
    main()
