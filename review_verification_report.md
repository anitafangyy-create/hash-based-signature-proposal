# 同行评审主张 vs 实际代码/正文 — 核对报告

**核对对象**：`paper.md` 正文 + 源代码（`wots.py` / `hbs_signature.py` / `unified_merkle_tree.py` / `experiment_v2.py` / `results_v2.json` / `README.md`）
**核对基准**：用户提供的《Major Revision》同行评审（2026-10-19）
**重要前提**：评审者自述仅依据 `paper.html` 正文、未独立执行代码。本报告补上了这一步。

> **一句话结论**：评审的**主要技术主张基本全部成立**，且与本仓库自己的 README 自述相互印证（README 第 9–13 行承认"该方向已被取代，应定位为 implementation audit 而非新签名方案"；第 47–51 行免责声明明确"不确立安全性、安全级别或 WOTS+/XMSS/LMS 符合性"）。本研究额外发现 4 处评审未点名、但确实存在的问题（见末尾"额外发现"）。

---

## 一、Major Comments 核对

### M1. 后量子安全性结论论证不足 —— ✅ 成立
- **证据**：
  - `paper.md:72`（§3.4）原文："existentially unforgeable under chosen-message attacks ... assuming SHA-256 is second-preimage resistant ... a 256-bit hash yields ~128-bit post-quantum security"。仅有"哈希够强 → 方案够强"的线性推导，无形式化归约、无归约损失量化、无单向性/碰撞抗性的完整假设集合。
  - 代码层面：`wots.py:65-73` 的 `chain` 用**无密钥**的 `H(b"WOTS-CHAIN"+x)`；`hbs_signature.py:46-50` 的 `H` 即裸 `sha256`。没有 FIPS 205 的 keyed `F`/地址分离，也就谈不上继承标准 WOTS+ 的 EUF-CMA 证明。
  - **多目标攻击**：Merkle 树有 `2^h` 个 OTS 公钥暴露于同一根下，论文未分析 N 个目标对安全边界的影响（§3.4 完全没有）。
  - README 第 47–51 行已自行声明"不确立安全级别"——与评审结论一致。
- **判断**：评审 M1 完全成立。摘要/§3.4 的"128-bit post-quantum security level"应降级为"设计目标参数"。

### M2. 与 FIPS 205 的符合性描述不准确 —— ✅ 成立
- **证据**：
  - `paper.md:34,50` 使用"WOTS+ as standardized in FIPS 205""Following FIPS 205"等措辞；但 `paper.md:82` 自承"plain SHA-256 with domain-separation prefixes ... deliberate simplification ... not for multi-target security claims"，且未采用 FIPS 205 的 PRF/F/H/H_msg 含密钥构造。
  - 代码确认：`wots.py` 全文件无 key/ADRS；`hbs_signature.py:46` 为裸哈希。
- **判断**：评审 M2 成立。区分"受启发/参考设计/标准兼容"三层次的建议恰当。论文在 §4、§7.3 已部分披露，但摘要、§2.2、§3.2 仍按 FIPS-205 派生框架表述，需收敛。

### M3. "WOTS+" 命名与安全属性需核实 —— ✅ 成立（且发现一处更严重缺口）
- **证据**：
  - `wots.py` 是 **WOTS 风格**方案，并非 FIPS 205 WOTS+：无 keyed `F`、无 ADRS、无随机化 `H_msg`（确定性 `H_message`）。
  - 域分离不足：`wots.py:72` 所有链、所有步都用同一前缀 `"WOTS-CHAIN"`，未按 FIPS 205 用地址区分链/步。
  - 校验和编码非标准：`wots.py:95,107` 用 `checksum.to_bytes(32,"big")` 取顶 3 位——数值可行，但与标准位宽/填充不同，且 `base_w` 为 LSB-first（`wots.py:46-62`），与 FIPS 205 位序不同，导致**无法通过官方 KAT 一致性**。
  - **更严重（评审未点名）**：一次性密钥**不可重用**在代码层面**未强制**。`hbs_signature.py:197-205` 的 `MSS.sign` 仅 `assert 0 <= leaf_index < n_leaves`，**不追踪已用索引**；`experiment_v2.py` 同样无追踪。调用方若重复同一 `leaf_index` 即静默复用 OTS 密钥——对有状态 HBS 是灾难性漏洞。论文 §6 把责任推给"钱包维护 bitmap"，但原型 API 本身不提供任何防护。

### M4. 实验不足以支撑 "Pareto 前沿" —— ✅ 成立
- **证据**：`experiment_v2.py:114-138` 只基准测试 `"lamport"` 与 `"wots"` 两种**本方案**后端；**完全没有**在相同环境测量 ML-DSA / SLH-DSA 的延迟。`paper.md:96-105`（Table 1）中标准方案的尺寸来自文献，延迟数据全缺。
- **判断**：size–latency Pareto 需要**所有方案**的两维数据，目前只有本方案一维，结论不成立。评审建议（同环境基准 / 收窄为尺寸对比）合理。

### M5. 统计可靠性与复现性不足 —— ✅ 成立（含评审未点名的缺失产物）
- **证据**：
  - `experiment_v2.py:114` 写死 `repeats=3`；`paper.md:90` 自承"median of three repetitions"。对亚毫秒级 Python 操作，3 次重复不足以刻画计时噪声；脚本未记录 CPU 型号/OS/Python 版本、无预热/GC/变频控制、无离散度或置信区间。
  - **评审未点名但确认存在**：`paper.md:84,180,186` 声称 KAT 向量序列化到 `kat_wots.json` 并可经 `python3 make_kat.py` 复现，但仓库内**两者均不存在**（glob 检索：`make_kat.py`、`kat_wots.json`、`*.rsp` 全部 0 命中）。即"通过确定性已知答案测试"的可复现性声明在当前仓库**无产物支撑**。
- **判断**：评审 M5 成立，且复现材料缺口比评审所述更具体。

### M6. 对比方案安全级别/使用条件不对齐 —— ✅ 成立（数值本身准确）
- **证据**：`paper.md:96-105`（Table 1）将本方案（声称 L1/128-bit）与 ML-DSA-44（**L2/192-bit**）、ML-DSA-65（**L3/256-bit**）并列——**安全级别不同**，只有 SLH-DSA-128s 是 L1。表格未就"有状态(2–128 次) vs 无状态"做同列对齐，仅在 §5.4 第 5 点脚注式说明（`paper.md:133`）。
- **判断**：评审 M6 的"公平性"担忧成立。**但需为论文说句公道话**：表中各标准方案的 pk/sig 绝对值（ML-DSA-44:1312/2420；ML-DSA-65:1952/3309；SLH-DSA-128s:32/7856；SLH-DSA-128f:32/17088）均正确，问题在"未按同级对比"而非"数据造假"。

---

## 二、Minor Comments 核对

### m7. 签名尺寸术语不统一 —— ✅ 成立（轻）
- **证据**：§3.1 Lamport OTS sig=8192 B（仅 OTS）；§3.2 WOTS+ sig=2144 B（仅 OTS）；§3.3/Table 完整 MSS sig = OTS sig + OTS pk + authpath。数值自洽（已验算：WOTS+ 2144+2144+224=**4512** ✓；Lamport 8192+16384+224=**24800** ✓）。但 Table 1 表头仅写 "Signature (B)"，未区分"纯 OTS"与"线上完整 MSS"。
- **判断**：建议表头明确"on-the-wire full MSS signature"。

### m8. 参考文献 [7] 标题错误 —— ✅ 成立（确凿）
- **证据**：`paper.md:165` 写 "[7] NIST, 'FIPS 205: **Module-Lattice-Based** Digital Signature Standard' (SLH-DSA/SPHINCS+)"。FIPS 205 实为 **Stateless Hash-Based** Digital Signature Standard；"Module-Lattice-Based"是 FIPS **204**（ML-DSA），而 [8]（`paper.md:166`）标题正确。即 [7] 标题与 [8] 标题**互换错误**。
- **补充**：正文 §2.3（`paper.md:38`）文字描述 FIPS 205 = stateless hash-based 是**正确的**，错误孤立在参考文献条目。另：论文称"SLH-DSA-128s ... uses n=16 internally"（`paper.md:106`）是**正确事实**，评审对此的谨慎提醒可保留，但不属于事实错误。

### m9. 创新性与相关工作讨论不足 —— ✅ 成立（方向性）
- **证据**：贡献为"实现 + 基准 + 对比 + 状态讨论"，无新构造/新证明。**本仓库 README 第 9–13 行已证明作者接受了这一批评**——明确"review feedback concluded the work should be positioned as an implementation audit rather than a new signature scheme"。
- **判断**：评审 m9 与作者自身转向一致。

### m10. 与 BIP-0360 关系需谨慎 —— 🟡 部分成立
- **证据**：论文 §1.2、§6 已讨论 BIP-0360 是"壳"、状态管理模型；`unified_merkle_tree.py` 探索了集成。但"状态持久化/回滚/钱包备份/共识改动"等集成风险在 `paper.md` 中**未深入分析**。
- **判断**：评审建议（区分"潜在价值"与"满足集成要求"）合理，但论文并非完全未触及，属"讨论深度不足"而非"完全遗漏"。

---

## 三、评审"第四节·性能自洽"验算 —— ✅ 评审算术正确，论文内部数字自洽
- 取自 `results_v2.json`（与 `paper.md` Table 2 完全一致）：
  - Lamport+MSS h=7 签名 **0.064 ms**；WOTS+MSS h=7 签名 **0.231 ms** → 比值 **3.61×**，额外 **0.167 ms**。
  - 尺寸 24800 → 4512 B → 比值 **5.50×**，缩小 **81.8%**。
- **判断**：评审第四节的换算精确，且论文 §5.4 自身表述（"~0.15 ms extra ... 5.5×"）内部一致。论文**仅有的越界**是把"本方案内部 WOTS+ vs Lamport"的压缩优势外推到"对 NIST 标准的 Pareto 优势"——这与 M4 同源。

---

## 四、额外发现（评审未点名，但代码/正文确有）
1. **KAT 复现产物缺失**：`make_kat.py`、`kat_wots.json` 在仓库中不存在，但 `paper.md` 附录与 §4 声称其存在并可复现 → KAT 可复现性声明当前**悬空**。
2. **一次性密钥复用未强制**：`hbs_signature.py:197-205` 与 `experiment_v2.py` 的签名接口不追踪已用 leaf，调用方可静默复用 → 有状态 HBS 的致命隐患，比"交给钱包管理"更严重。
3. **§7.3 自相矛盾**：`paper.md:147` 写 "No domain separation. We use prefix-separated SHA-256"，与 §4/代码实际使用的 `"WOTS-CHAIN"/"MSS-LEAF"/"MSS-NODE"` 前缀矛盾。应改为"prefix-based, not keyed"。
4. **跨级对比公平性**：Table 1 把 L1 本方案与 L2/L3 的 ML-DSA 并列，评审点到安全级别依据但未充分展开——建议明确只与**同级（L1）的 SLH-DSA-128s** 直接比尺寸，并强调状态差异。

---

## 五、给作者的修订优先级（与评审 P0–P2 对齐，已据实测收紧）
- **P0**：收敛 §3.4 / 摘要的安全主张为"设计目标"；补安全模型与假设。
- **P0**：将"FIPS 205 / WOTS+"改为"受 FIPS 205 启发的研究原型 / WOTS 风格链"，列差异表。
- **P1**：MSS 接口强制一次性使用（追加 used-bitmap 或至少断言防重）；补 `make_kat.py` + `kat_wots.json` 真实产物。
- **P1**：Pareto 结论要么删除、要么同环境补 ML-DSA/SLH-DSA 基准；Table 1 标注各方案安全级别与状态。
- **P2**：修正参考文献 [7] 标题；统一签名尺寸术语；修 §7.3 自相矛盾；补 BIP-0360 集成风险讨论。

> 备注：当前投稿稿件据 README 已迁至同级目录 `../jce-implementation-audit/`，本仓库为可追溯的早期草稿。若需核对"修订后版本"是否真正落实上述意见，应到该目录核对，而非本仓库。
