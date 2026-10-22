"""V2 charts: Lamport vs WOTS+ (explicit and compact) and cross-scheme sizes."""
import json
from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

OUT = Path(__file__).resolve().parent
rows = json.loads((OUT / "results_v2.json").read_text())

plt.rcParams.update({"font.size": 11, "axes.grid": True, "grid.alpha": 0.3})

lamport = [r for r in rows if r["kind"] == "lamport"]
wots_exp = [r for r in rows if r["kind"] == "wots" and not r["compact"]]
wots_cmp = [r for r in rows if r["kind"] == "wots" and r["compact"]]

# ------------------------------------------------------------------
# Fig 5: Lamport vs WOTS+ (explicit and compact) signature size
# ------------------------------------------------------------------
hs = [r["height"] for r in lamport]
fig, ax = plt.subplots(figsize=(9, 5.5))
ax.plot(hs, [r["signature_bytes"] / 1024 for r in lamport],
        "o-", label="Lamport OTS + Merkle", color="#888888", lw=2, markersize=8)
ax.plot(hs, [r["signature_bytes"] / 1024 for r in wots_exp],
        "s-", label="WOTS+ + Merkle (explicit)", color="#C44E52", lw=2, markersize=8)
ax.plot(hs, [r["signature_bytes"] / 1024 for r in wots_cmp],
        "^-", label="WOTS+ + Merkle (compact)", color="#4C72B0", lw=2, markersize=8)
ax.set_xlabel("Tree height h (supports 2^h signatures)")
ax.set_ylabel("Signature size (KiB)")
ax.set_title("WOTS+ compression effect: signature size vs. tree height")
ax.legend()
for r in wots_exp:
    ax.annotate(f"{r['signature_bytes']:,} B",
                (r["height"], r["signature_bytes"] / 1024),
                textcoords="offset points", xytext=(5, 8), fontsize=8)
for r in wots_cmp:
    ax.annotate(f"{r['signature_bytes']:,} B",
                (r["height"], r["signature_bytes"] / 1024),
                textcoords="offset points", xytext=(5, -14), fontsize=8)
plt.tight_layout()
plt.savefig(OUT / "fig5_wots_compression.png", dpi=150)
plt.close()

# ------------------------------------------------------------------
# Fig 6: Updated cross-scheme signature size comparison
# ------------------------------------------------------------------
schemes = [
    ("secp256k1 Schnorr", 64, "#888888"),
    ("LMS SHA256 H10 (stateful)", 1452, "#8C8C8C"),
    ("XMSS SHA256_10 (stateful)", 2500, "#8C8C8C"),
    ("ML-DSA-44", 2420, "#4C72B0"),
    ("ML-DSA-65", 3309, "#4C72B0"),
    ("SLH-DSA-128s", 7856, "#55A868"),
    ("SLH-DSA-128f", 17088, "#55A868"),
    ("Lamport+MSS (h=7)", lamport[-1]["signature_bytes"], "#AAAAAA"),
    ("WOTS+MSS explicit (h=7)", wots_exp[-1]["signature_bytes"], "#C44E52"),
    ("WOTS+MSS compact (h=7)", wots_cmp[-1]["signature_bytes"], "#4C72B0"),
]
names = [s[0] for s in schemes]
sizes = [s[1] for s in schemes]
colors = [s[2] for s in schemes]

fig, ax = plt.subplots(figsize=(10, 6.5))
bars = ax.barh(names, sizes, color=colors)
ax.set_xscale("log")
ax.set_xlabel("Signature size (bytes, log scale)")
ax.set_title("Post-quantum signature size: WOTS+MSS vs. NIST standards")
for bar, v in zip(bars, sizes):
    ax.text(v * 1.1, bar.get_y() + bar.get_height() / 2,
            f"{v:,} B", va="center", fontsize=10)
plt.tight_layout()
plt.savefig(OUT / "fig6_cross_scheme_v2.png", dpi=150)
plt.close()

# ------------------------------------------------------------------
# Fig 7: Latency comparison (signing + verification, explicit/compact)
# ------------------------------------------------------------------
fig, axes = plt.subplots(1, 2, figsize=(12, 5))
ax = axes[0]
ax.plot(hs, [r["sign_ms"] for r in lamport], "o-",
        label="Lamport", color="#888888", lw=2)
ax.plot(hs, [r["sign_ms"] for r in wots_exp], "s-",
        label="WOTS+", color="#C44E52", lw=2)
ax.set_xlabel("Tree height h")
ax.set_ylabel("Sign time (ms)")
ax.set_title("Signing latency")
ax.legend()

ax = axes[1]
ax.plot(hs, [r["verify_ms"] for r in lamport], "o-",
        label="Lamport", color="#888888", lw=2)
ax.plot(hs, [r["verify_ms"] for r in wots_exp], "s-",
        label="WOTS+ explicit", color="#C44E52", lw=2)
ax.plot(hs, [r["verify_ms"] for r in wots_cmp], "^-",
        label="WOTS+ compact", color="#4C72B0", lw=2)
ax.set_xlabel("Tree height h")
ax.set_ylabel("Verify time (ms)")
ax.set_title("Verification latency")
ax.legend()
plt.tight_layout()
plt.savefig(OUT / "fig7_latency_v2.png", dpi=150)
plt.close()

print("New charts:")
for f in ["fig5_wots_compression.png", "fig6_cross_scheme_v2.png",
          "fig7_latency_v2.png"]:
    print(" -", f)
