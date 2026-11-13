Follow-up to release v1.1-revision (formatting and caption wording only, no result changes)

Files changed since the v1.1-revision file set (6):
  easa_sim/scripts/make_figures.py       - Table S25 generator: [!htb] float, two panels, note wording
  easa_sim/scripts/shorten_captions.py   - caption dictionary synced with the revised manuscript
  figures/v4/tab_results.tex             - Table 8 caption "Primary results over 30 paired seeds", note wording
  figures/v4/tab_results_full.tex        - Table S25: two panels, [!htb], note wording
  figures/v4/tab_replay.tex              - Table 11 caption shortened
  figures/v4/tab_lowbattery.tex          - Table 12 caption shortened

Apply (VS Code terminal, in C:\paper\Sensors_Code_202610\easa-repo):
  1. Extract this zip over the repository root (keeps the folder structure).
  2. git status                      -> the six files should be listed as modified
  3. git add -A
  4. git commit -m "Caption and table-layout follow-up to v1.1-revision (no result changes)"
  5. git push origin main
The v1.1-revision tag and release stay as they are; the manuscript cites the release, not the branch.
