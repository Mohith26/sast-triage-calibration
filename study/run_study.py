"""Calibrated SAST triage on OWASP Benchmark Java v1.2 + Semgrep OSS java rules.

Population: every Benchmark test case that Semgrep flags with a CWE-matching finding.
Task: predict whether the flagged test case is a real vulnerability (true positive) or not.
Compares a per-rule prior with a small code-token logistic regression, under two splits:
random 5-fold and 5-fold grouped by the test case's dataflow ("propagator") template.
"""
import json
import re
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import brier_score_loss, roc_auc_score
from sklearn.model_selection import GroupKFold, StratifiedKFold
from sklearn.pipeline import make_pipeline

sys.path.insert(0, str(Path(__file__).parent))
import features  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
TESTCODE = ROOT / "BenchmarkJava/src/main/java/org/owasp/benchmark/testcode"
SEED = 0
RECALL_TARGET = 0.95


def ece(y, p, bins=10):
    edges = np.linspace(0, 1, bins + 1)
    idx = np.clip(np.digitize(p, edges) - 1, 0, bins - 1)
    total = 0.0
    for b in range(bins):
        m = idx == b
        if m.any():
            total += m.mean() * abs(y[m].mean() - p[m].mean())
    return total


def load(semgrep_json):
    exp = pd.read_csv(ROOT / "BenchmarkJava/expectedresults-1.2.csv", comment="#", header=None,
                      names=["test", "cat", "real", "cwe"])
    exp["real"] = exp.real.astype(str).str.strip().str.lower().eq("true")
    res = json.load(open(semgrep_json))["results"]
    rows = []
    for r in res:
        t = re.search(r"(BenchmarkTest\d+)", r["path"]).group(1)
        cw = r["extra"]["metadata"].get("cwe", [])
        cw = [cw] if isinstance(cw, str) else cw
        rows.append({"test": t, "rule": r["check_id"].split(".")[-1],
                     "cwes": [int(x) for c in cw for x in re.findall(r"CWE-(\d+)", c)]})
    f = pd.DataFrame(rows).merge(exp, on="test")
    f = f[[c in cs for c, cs in zip(f.cwe, f.cwes)]]
    # one row per flagged test case; keep the (alphabetically first) matching rule
    flagged = f.sort_values("rule").groupby("test").first().reset_index()
    src = {t: (TESTCODE / f"{t}.java").read_text() for t in flagged.test}
    flagged["template"] = [features.template_id(src[t]) for t in flagged.test]
    flagged["code"] = [code_text(src[t]) for t in flagged.test]
    flagged["code_nostr"] = [code_text(src[t], mask_strings=True) for t in flagged.test]
    flagged["code_nolit"] = [code_text(src[t], True, True) for t in flagged.test]
    return exp, flagged


def code_text(src, mask_strings=False, mask_numbers=False):
    """Body of the servlet from doPost on, comments and test names stripped.

    mask_strings replaces every string literal with STR, so the model cannot read
    hints such as "safe!" or "This_should_always_happen". mask_numbers replaces
    integer literals with NUM, which removes the values needed to evaluate the
    constant conditions the Benchmark uses to kill taint.
    """
    i = src.find("public void doPost")
    body = src[i:] if i >= 0 else src
    body = re.sub(r"//.*", " ", body)
    body = re.sub(r"BenchmarkTest\d+", "T", body)
    if mask_strings:
        body = re.sub(r'"(?:[^"\\]|\\.)*"', " STR ", body)
    if mask_numbers:
        body = re.sub(r"\b\d+\b", " NUM ", body)
    return body


def rule_prior(train, test):
    pri = train.groupby("rule").real.mean()
    return test.rule.map(pri).fillna(train.real.mean()).to_numpy()


def text_model(train, test, col="code"):
    pipe = make_pipeline(
        TfidfVectorizer(token_pattern=r"[A-Za-z_][A-Za-z0-9_]*|[^\sA-Za-z0-9_]", ngram_range=(1, 3),
                        min_df=2, sublinear_tf=True),
        LogisticRegression(C=4.0, max_iter=2000),
    )
    cal = CalibratedClassifierCV(pipe, method="sigmoid", cv=3)
    cal.fit(train[col], train.real.astype(int))
    p_tr = cal.predict_proba(train[col])[:, 1]
    return cal.predict_proba(test[col])[:, 1], p_tr


def threshold_for_recall(y, p, target):
    pos = np.sort(p[y == 1])
    k = int(np.floor((1 - target) * len(pos)))
    return pos[k] if len(pos) else 0.5


VIEWS = {"text": "code", "text_strings_masked": "code_nostr", "text_literals_masked": "code_nolit"}


def evaluate(df, splitter, groups=None):
    y = df.real.to_numpy().astype(int)
    out = {"prior": np.zeros(len(df))}
    out.update({k: np.zeros(len(df)) for k in VIEWS})
    kept = {k: [] for k in VIEWS}
    fp_cut = {k: [] for k in VIEWS}
    split = splitter.split(df, y, groups) if groups is not None else splitter.split(df, y)
    for tr, te in split:
        a, b = df.iloc[tr], df.iloc[te]
        out["prior"][te] = rule_prior(a, b)
        yt = b.real.to_numpy().astype(int)
        for k, col in VIEWS.items():
            p_te, p_tr_in = text_model(a, b, col)
            out[k][te] = p_te
            # threshold set on the training fold's (calibrated, in-sample) scores for 95% recall
            thr = threshold_for_recall(a.real.to_numpy().astype(int), p_tr_in, RECALL_TARGET)
            keep = p_te >= thr
            kept[k].append(((keep & (yt == 1)).sum(), (yt == 1).sum()))
            fp_cut[k].append(((~keep & (yt == 0)).sum(), (yt == 0).sum()))
    res = {}
    for k, p in out.items():
        res[k] = {"auroc": roc_auc_score(y, p), "brier": brier_score_loss(y, p), "ece": ece(y, p)}
    for k in VIEWS:
        res[k]["recall_at_train_threshold"] = sum(a for a, _ in kept[k]) / sum(b for _, b in kept[k])
        res[k]["fp_suppressed_at_train_threshold"] = (
            sum(a for a, _ in fp_cut[k]) / sum(b for _, b in fp_cut[k]))
    return res, out


def main(semgrep_json):
    exp, df = load(semgrep_json)
    df = df.sample(frac=1.0, random_state=SEED).reset_index(drop=True)
    summary = {
        "n_test_cases": len(exp),
        "n_flagged": len(df),
        "flagged_precision": float(df.real.mean()),
        "n_templates_in_flagged": int(df.template.nunique()),
    }
    rnd, _ = evaluate(df, StratifiedKFold(5, shuffle=True, random_state=SEED))
    grp, _ = evaluate(df, GroupKFold(5), groups=df.template)
    summary["random_split"] = rnd
    summary["template_held_out"] = grp
    return summary


if __name__ == "__main__":
    s = main(sys.argv[1] if len(sys.argv) > 1 else str(ROOT / "semgrep_java.json"))
    print(json.dumps(s, indent=2, default=float))
