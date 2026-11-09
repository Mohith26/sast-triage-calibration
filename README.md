# sast-triage-calibration

How much of a "calibrated SAST triage" model's apparent skill on the OWASP Benchmark comes from reading the code's dataflow, and how much comes from string literals that give the answer away?

I ran Semgrep's open-source Java rules over OWASP Benchmark Java v1.2, kept every test case Semgrep flags with a CWE-matching finding, and trained a small, calibrated triage model (TF-IDF over the servlet body, logistic regression, Platt scaling) to predict whether each flagged case is a real vulnerability. Then I repeated it with string literals masked, and with string and integer literals masked, under two splits: random 5-fold and 5-fold grouped by dataflow template.

## Result

Semgrep (OSS rules, `semgrep-rules@16b9e6d`) flags 1,670 of the 2,740 test cases; 66.9% of those are real vulnerabilities, so 552 flagged cases are false positives.

Template-held-out 5-fold CV (dataflow templates never shared between train and test):

| triage model | AUROC | Brier | ECE | recall at train-set 95% threshold | false positives suppressed |
|---|---|---|---|---|---|
| per-rule prior (no code) | 0.676 | 0.193 | 0.033 | - | - |
| code tokens | 0.984 | 0.041 | 0.020 | 0.943 | 94.9% |
| code tokens, strings masked | 0.890 | 0.130 | 0.059 | 0.928 | 41.8% |
| code tokens, strings and integers masked | 0.881 | 0.134 | 0.057 | 0.930 | 38.9% |

Random 5-fold CV, same models:

| triage model | AUROC | Brier | ECE | recall at train-set 95% threshold | false positives suppressed |
|---|---|---|---|---|---|
| per-rule prior (no code) | 0.676 | 0.193 | 0.018 | - | - |
| code tokens | 0.994 | 0.030 | 0.022 | 0.937 | 97.1% |
| code tokens, strings masked | 0.908 | 0.115 | 0.038 | 0.930 | 52.2% |
| code tokens, strings and integers masked | 0.899 | 0.120 | 0.041 | 0.927 | 47.5% |

What I take from it:

1. **More than half of the false-positive reduction is literal tells.** With literals visible, the model's strongest features are strings like `"This_should_always_happen"` (13% of the 222 flagged cases containing it are real) and `"This should never happen"` (97% of 220 are real), plus `"alsosafe"` and `"bobs_your_uncle"`. Masking strings cuts false positives suppressed at roughly 95% recall from 94.9% to 41.8% on held-out templates. A triage model scored on the Benchmark with raw source will look far better than it would on real code.
2. **What survives masking is real structure.** After masking, the top features are the constant-arithmetic conditionals the Benchmark uses to kill taint (tokens like `* ) +` and `+ num >`), ESAPI `encodeForHTML(param)`, and helper-call shapes such as `getTheValue(` and `doSomething(param`. That is about 40% of false positives removed at about 93% recall, from a model small enough to run on every commit.
3. **Thresholds transfer a little short.** A threshold set for 95% recall on the training folds lands at 92.8-94.3% recall on unseen templates, so a team that sets thresholds on one codebase should budget a couple of points of recall drift on the next.
4. **Calibration holds up better than ranking.** ECE stays under 0.06 in every configuration, but Brier score triples once literals are masked; the confidence is honest about being less sure, which is the behavior you want before thresholding.

## What was and wasn't run

- Run: Semgrep 1.184.0 with the 113 rules in `semgrep-rules/java` at commit `16b9e6d` against `BenchmarkJava` at commit `d4f6f3a`, on Apple Silicon arm64 (scan takes about 20 s). Scoring follows the Benchmark convention: a finding counts for a test case only when its CWE matches the test case's CWE. The crypto category scores 0 because the OSS DES rules are tagged CWE-326 while the Benchmark expects CWE-327; I did not remap CWEs.
- Run: the triage models above, seed 0, in `study/run_study.py`; the raw numbers are in `study/results.json`.
- Not run: any LLM triage, any commercial SAST tool, or any real-world codebase. The Benchmark is synthetic, so the masked-literal numbers are a better guide than the raw ones but still not a real-world estimate.
- Dataflow templates are recovered heuristically (`study/features.py`): the normalized `bar` propagation block, or the body of the `doSomething` helper when there is one. That yields 126 templates over the whole Benchmark (108 among flagged cases).

## Reproduce

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
./run.sh            # clones pinned inputs, runs Semgrep, writes study/results.json
python -m pytest -q # unit tests for template grouping, masking, ECE and thresholding
```
