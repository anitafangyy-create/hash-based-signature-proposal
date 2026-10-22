"""One-shot rewrite using line-based section replacement."""
from pathlib import Path

p = Path("/Users/fangyuanyuan/Doubao/chats/2026-09-28/new-chat/pqc_research/paper_jce.md")
text = p.read_text()
lines = text.split("\n")

def find_line(prefix):
    for i, l in enumerate(lines):
        if l.startswith(prefix):
            return i
    raise ValueError(prefix)

# Section boundaries
i_title = 0
i_abs = find_line("**Abstract**")
i_intro = find_line("## 1. Introduction")
i_related = find_line("## 2. Related Work")
i_sec5 = find_line("## 5. Security Analysis")
i_sec6 = find_line("## 6. Complexity")

# New title
lines[i_title] = "# Engineering Hash-Based Post-Quantum Signatures for Bitcoin: Winternitz Trade-offs, Merkle Aggregation, and P2MR Integration"

# New abstract: replace from "**Abstract**" to the "---" before intro
# Find the "---" line right before intro
i_sep = i_intro - 1
while lines[i_sep].strip() == "":
    i_sep -= 1
# i_sep should be "---"

new_abstract = """**Abstract**

Quantum attacks on elliptic-curve cryptography motivate migration paths for blockchain systems, but standardized post-quantum signatures introduce substantial key or signature overhead. This study investigates the engineering trade-offs of stateful hash-based signatures for Bitcoin-oriented post-quantum migration. We implement Lamport and configurable Winternitz hash-chain signatures with Merkle aggregation, derive analytical models for signature size, hash-chain work, and signer state, and validate them using Python and C implementations. For SHA-256 with $w \\in \\{4, 16, 256\\}$, the evaluated configurations expose a clear size–latency trade-off, reducing the cryptographic payload from 4,384 B to 1,216 B as $w$ increases while increasing hash-chain computation. A Bitcoin Pay-to-Merkle-Root (P2MR) integration prototype further quantifies the complete witness overhead, demonstrating that protocol-level cost differs substantially from isolated signature size. Compared with standardized stateless alternatives such as ML-DSA and SLH-DSA, the results identify signer state management as the principal cost exchanged for compact hash-based payloads. These findings characterize the deployment envelope of stateful hash-based authentication for post-quantum Bitcoin migration rather than proposing a new cryptographic primitive.
"""

new_intro = """## 1. Introduction

Bitcoin's transaction graph is permanently public, and the elliptic-curve public keys embedded in unspent outputs will remain exposed indefinitely. The anticipated arrival of cryptographically relevant quantum computers (CRQCs) threatens these keys via Shor's algorithm [1]; NIST has mandated post-quantum migration by 2035 [2]. For Bitcoin, the long-exposure risk is not simply a matter of swapping signature algorithms: it couples three system constraints simultaneously,

$$\\text{security} + \\text{on\\!-\\!chain\\! footprint} + \\text{deployability}.$$

Existing post-quantum choices occupy different points in this space. ML-DSA (FIPS 204 [12]) is stateless and standardized but carries 1.3 KB public keys and 2.4–3.3 KB signatures. SLH-DSA (FIPS 205 [7]) is hash-based and stateless but produces 7.9–17 KB signatures. Stateful hash-based signatures—Lamport [4], Merkle [5], and Winternitz hash chains—offer a 32-byte public commitment and the minimal security assumption (collision-resistant hashes), at the cost of persistent signer state and one-time-key capacity. The engineering question this paper addresses is:

> How much on-chain space can statefulness actually save, and at what computational and operational cost?

BIP-0360 (Pay-to-Merkle-Root, P2MR) [3] proposes a soft fork that removes the Taproot key-path spend, leaving a script-tree output type committing only to a 32-byte Merkle root. P2MR itself is not a post-quantum signature; it is a PQ-compatible commitment shell that (i) stops long-exposure leakage of secp256k1 public keys and (ii) reserves the `OP_SUCCESSx` upgrade path for future verification opcodes. This paper studies the signature layer that such a shell would host, and quantifies the gap between algorithm-level payload and protocol-level witness.

**Contributions.**

1. **Analytical model.** We derive closed-form expressions relating the Winternitz parameter $w$, the OTS payload, the Merkle authentication path, and signer secret memory, and we distinguish cryptographic payload from complete Bitcoin witness.
2. **Reproducible implementation.** We implement the evaluated construction in Python and C, with deterministic known-answer tests, tamper-rejection checks, and cross-validation against the FIPS 205 parameter set.
3. **Empirical trade-off characterization.** We sweep $w \\in \\{4, 16, 256\\}$ and quantify the resulting size–latency trade-off rather than treating Winternitz hash chains as a single fixed operating point.
4. **Bitcoin P2MR deployment evaluation.** We construct a P2MR-oriented prototype, report witness bytes and transaction weight, and separate the cost of the cryptographic signature from the cost of Merkle authentication, leaf scripts, and control blocks.

The remainder of this paper is organized as follows. Section 2 reviews related work. Section 3 fixes notation and the threat model. Section 4 presents the parameterized construction. Section 5 states security and operational considerations. Section 6 derives the size/work/state model. Section 7 reports experiments. Section 8 evaluates the P2MR deployment. Section 9 discusses an extension to post-quantum confidentiality. Section 10 concludes.
"""

new_sec5 = """## 5. Security and Operational Considerations

The evaluated construction is not presented as a new cryptographic primitive, and we do not claim a new security reduction. Its security rationale follows established Winternitz and Merkle signature principles. We state the assumptions and operational limits explicitly.

### 5.1 Security assumptions

The construction relies on three layers, each inherited from prior analysis:

- **Hash-chain security.** Each Winternitz chain is an iterated one-way function. Forgability requires second-preimage resistance of $H$, which Grover's algorithm degrades only quadratically (256-bit hash → ~128-bit post-quantum security).
- **Checksum binding.** The $L_2$ checksum digits force an attacker to simultaneously forge low-digit and high-digit chains; this prevents the naive forgery of extending every chain forward.
- **Merkle commitment.** The root is a collision-resistant hash of all OTS public keys; opening a leaf requires a valid authentication path.

### 5.2 Implementation limits (honest disclosure)

Our chaining function uses prefix-separated SHA-256, $H(\\text{"WOTS-CHAIN"} \\| x)$, with no per-chain key and no address input. This is a simplified reference construction. It is **not byte-compatible** with FIPS 205 WOTS+, which uses a keyed `thash` bound to `PK.seed` and an address updated at every chain step. Consequently:

- Our output bytes do not match the official NIST KAT `.rsp` files (see Appendix B).
- We do not inherit the full multi-target security analysis of standardized WOTS+.
- A production deployment should replace the prefix-separated chain with the FIPS 205 keyed `thash` before claiming a NIST security level.

The algebraic structure—base-$w$ digit decomposition, checksum, chain-length verification equation—is identical to FIPS 205.

### 5.3 One-time-key and state threats

Each OTS key pair may sign exactly once. Reusing a key pair for two messages reveals two chain positions $d_i^{(1)}, d_i^{(2)}$; their difference exposes the hash-chain interval and permits forgery. Three failure modes:

1. **Accidental reuse**: a wallet bug signs twice with the same leaf. Mitigation: atomic state update before broadcast.
2. **State rollback**: an attacker reverts the wallet state file, causing future reuse. Mitigation: append-only state log with checksums.
3. **Leaf exhaustion**: if $N=2^h$ leaves are consumed, no further signatures are possible. Mitigation: choose $h$ for the expected wallet lifetime.

### 5.4 Side channels and fault injection

This Python prototype is not constant-time; chain iteration count depends on secret digits. A production C/Rust implementation must use constant-time hash calls and constant-memory chain traversal. Fault injection during chain iteration could skip intermediate hash calls; verification must check that the full chain length was traversed, not just the endpoint. We flag these as engineering hardening requirements, not addressed in this prototype.

### 5.5 Stateful vs. stateless trade-off

Our Merkle construction is stateful. SLH-DSA (FIPS 205) removes state by layering a hypertree of XMSS instances with FORS, at the cost of 7.9–17 KB signatures. Our trade-off curve shows that a stateful configuration can reach 1.2 KB; the extra 6–16 KB in SLH-DSA is the price of eliminating the state file.
"""

# Reconstruct:
# [0] title
# [1..i_abs-1] blank lines (keep)
# abstract block: from i_abs to i_sep (replaced)
# blank line
# intro block: from i_intro to i_related-1 (replaced)
# [i_related..] rest

# Build new lines list
out = []
out.append(lines[0])  # title
out.append("")
out.extend(new_abstract.split("\n"))
out.append("")
out.append("---")
out.append("")
out.extend(new_intro.split("\n"))
# Now append everything from i_related onward
out.extend(lines[i_related:])

text2 = "\n".join(out)

# Now replace Section 5 block (from "## 5." to "## 6.")
# Find in text2
import re
m5 = re.search(r"## 5\. Security Analysis\n\n.*?(?=\n## 6\. Complexity)", text2, re.DOTALL)
assert m5, "sec5 not found in new text"
text2 = text2[:m5.start()] + new_sec5 + text2[m5.end():]

# Now fix Section 6.1 size formulas
old_s61 = """### 6.1 Size formulas

For parameters $(n, w, h)$:

$$|\\sigma_{\\text{MSS}}| = L \\cdot n + h \\cdot n = n(L_1+L_2+h)$$

where the $L \\cdot n$ term is the WOTS+ signature plus public key (both transmitted) and the $h \\cdot n$ term is the authentication path. The expected number of hash iterations during signing is

$$\\mathbb{E}[\\text{work}] = L \\cdot \\frac{w-1}{2}$$

since each digit is uniform in $[0, w-1]$."""

new_s61 = """### 6.1 Size and accounting formulas

For parameters $(n, w, h)$ we distinguish three quantities, because the algorithm-level payload and the Bitcoin witness are not the same:

1. **OTS signature component** (what the signer produces):
$$S_{\\text{OTS}} = L \\cdot n, \\qquad L = L_1 + L_2.$$
   At $w=16, n=32$: $S_{\\text{OTS}} = 67 \\cdot 32 = 2{,}144$ B.

2. **Merkle authentication component** (the path to the root):
$$S_{\\text{auth}} = h \\cdot n.$$
   At $h=4$: $S_{\\text{auth}} = 4 \\cdot 32 = 128$ B.

3. **Cryptographic MSS payload** (what a verifier needs to check membership, assuming the OTS public key is reconstructed from the signature and message):
$$S_{\\text{MSS}} = S_{\\text{OTS}} + S_{\\text{auth}} = n(L + h).$$
   At $w=16, h=4$: $S_{\\text{MSS}} = 2{,}144 + 128 = 2{,}272$ B.

However, a Bitcoin P2MR witness must additionally transmit the OTS public key (so the verifier can re-derive the leaf hash without a trusted setup), the leaf script, and the control block. The complete witness is therefore

$$S_{\\text{witness}} = S_{\\text{OTS}} + L \\cdot n + S_{\\text{auth}} + S_{\\text{script}} + S_{\\text{control}},$$

where the second $L \\cdot n$ is the transmitted OTS public key. At $w=16, h=4$ this is $2{,}144 + 2{,}144 + 128 + 3 + 33 \\approx 4{,}452$ B. This decomposition explains why the algorithm-level MSS payload (2,272 B) is roughly half of the on-chain witness (~4.3 KB)—a gap that a deployment evaluation must report explicitly.

The expected number of hash iterations during signing is

$$\\mathbb{E}[\\text{work}] = L \\cdot \\frac{w-1}{2}$$

since each digit is uniform in $[0, w-1]$."""

assert old_s61 in text2, "s61 not found"
text2 = text2.replace(old_s61, new_s61)

p.write_text(text2)
print(f"[rewritten] {p} ({len(text2)} chars)")
