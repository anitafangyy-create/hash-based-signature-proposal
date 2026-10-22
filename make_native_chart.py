"""make_native_chart.py — figure for the native cross-implementation benchmark.

Prefers native_results_sessions.json (cross-session medians); falls back to
native_results.json (single session). Writes fig8_native_benchmark.png.
"""
import json
from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

OUT = Path(__file__).resolve().parent
sess_path = OUT / "native_results_sessions.json"
single_path = OUT / "native_results.json"

if sess_path.exists():
    S = json.loads(sess_path.read_text())["summary"]

    def by_scheme(name):
        for e in S.values():
            if e.get("scheme") == name:
                return e
        raise KeyError(name)

    def row(e):
        return {
            "keygen_ms": e["keygen_ms"]["median"],
            "sign_ms": e["sign_ms"]["median"],
            "verify_ms": e["verify_ms"]["median"],
            "sig": e.get("sig", e.get("sig_bytes")),
        }

    rows = [
        ("ML-DSA-44 (L2)",              row(by_scheme("ML-DSA-44")), "#4C72B0"),
        ("ML-DSA-65 (L3)",              row(by_scheme("ML-DSA-65")), "#4C72B0"),
        ("SLH-DSA-128s (L1)",           row(by_scheme("SLH-DSA-SHA2-128s (PQClean)")), "#55A868"),
        ("SLH-DSA-128f (L1)",           row(by_scheme("SLH-DSA-SHA2-128f (PQClean)")), "#55A868"),
        ("Lamport+MSS h=7",             row(S["lamport|False|7"]), "#AAAAAA"),
        ("WOTS+MSS h=7 (explicit)",     row(S["wots|False|7"]), "#C44E52"),
        ("WOTS+MSS h=7 (compact)",      row(S["wots|True|7"]), "#E17C7C"),
    ]
else:  # single-session fallback
    d = json.loads(single_path.read_text())
    std = {r["scheme"]: r for r in d["standards"]}
    proto = d["prototype"]
    rows = [
        ("ML-DSA-44 (L2)", std["ML-DSA-44"], "#4C72B0"),
        ("ML-DSA-65 (L3)", std["ML-DSA-65"], "#4C72B0"),
        ("SLH-DSA-128s (L1)", std["SLH-DSA-SHA2-128s (PQClean)"], "#55A868"),
        ("SLH-DSA-128f (L1)", std["SLH-DSA-SHA2-128f (PQClean)"], "#55A868"),
        ("Lamport+MSS h=7", [r for r in proto if r["kind"] == "lamport" and r["h"] == 7][0], "#AAAAAA"),
        ("WOTS+MSS h=7 (explicit)", [r for r in proto if r["kind"] == "wots" and not r["compact"] and r["h"] == 7][0], "#C44E52"),
        ("WOTS+MSS h=7 (compact)", [r for r in proto if r["kind"] == "wots" and r["compact"] and r["h"] == 7][0], "#E17C7C"),
    ]
    rows = [(n, {"keygen_ms": r["keygen_ms"], "sign_ms": r["sign_ms"],
                 "verify_ms": r["verify_ms"], "sig": r.get("sig", r.get("sig_bytes"))}, c)
            for n, r, c in rows]

names = [r[0] for r in rows]
sign = [r[1]["sign_ms"] for r in rows]
verify = [r[1]["verify_ms"] for r in rows]
size = [r[1]["sig"] for r in rows]

plt.rcParams.update({"font.size": 10.5, "axes.grid": True, "grid.alpha": 0.3})
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))

y = list(range(len(names)))
h = 0.38
ax1.barh([i + h / 2 for i in y], sign, height=h, color="#C44E52", label="sign")
ax1.barh([i - h / 2 for i in y], verify, height=h, color="#4C72B0", label="verify")
ax1.set_yticks(y)
ax1.set_yticklabels(names)
ax1.set_xscale("log")
ax1.set_xlabel("Latency (ms, log scale)")
ax1.set_title("Same-machine latency (cross-session median, 3 sessions)")
ax1.legend(loc="lower right")
for i, v in enumerate(sign):
    ax1.text(v * 1.12, i + h / 2, f"{v:.3g}", va="center", fontsize=8)
for i, v in enumerate(verify):
    ax1.text(v * 1.12, i - h / 2, f"{v:.3g}", va="center", fontsize=8)
ax1.set_xlim(left=min(sign + verify) * 0.4, right=max(sign + verify) * 5)

ax2.barh(y, size, color=[r[2] for r in rows])
ax2.set_yticks(y)
ax2.set_yticklabels(["" for _ in y])
ax2.set_xscale("log")
ax2.set_xlabel("Signature size (bytes, log scale)")
ax2.set_title("Signature size")
ax2.set_xlim(right=max(size) * 4)
for i, v in enumerate(size):
    ax2.text(v * 1.08, i, f"{v:,} B", va="center", fontsize=8)

fig.suptitle("Native cross-implementation benchmark: stateful Merkle prototype vs. NIST standards\n"
             "(median of 3 sessions; our rows are stateful, capacity 2^7=128 signatures/key; standard rows stateless)",
             fontsize=11)
plt.tight_layout(rect=[0, 0, 1, 0.94])
plt.savefig(OUT / "fig8_native_benchmark.png", dpi=300)
plt.close()
print("wrote fig8_native_benchmark.png")
