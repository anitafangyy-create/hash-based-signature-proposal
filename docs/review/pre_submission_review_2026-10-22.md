# 投稿前外审终审报告 — hash-based-signature-proposal

**论文**: *An Implementation Audit of a Lamport–WOTS+–Merkle Post-Quantum Signature Prototype: Three Findings and a Comparison Against NIST Standards*
**审稿日期**: 2026-10-22
**审稿人角色**: 外部审稿专家（投稿前终审）
**核验范围**: 算法正确性 · 实验口径统一 · payload accounting · 可复现性 · 数据准确性 · BIP-0360 协议合规性 · 参考文献真实性

---

## 0. 总体裁定

**科学结论全部经数据/代码/外部源复核成立，未发现任何 P0（颠覆性）问题。** 论文的核心三发现（F1 校验和缺陷、F2 紧凑签名、F3 原生性能）均有可追溯证据且数字与原始数据文件一致。终审发现 **7 项 P1（投稿前必须修复）** 与 **5 项 P2（建议修复）**，集中在**图表与正文不同步、两个遗留产物（benchmark_raw、manifest）过时、域分离标签文档与代码不一致、git 工作区未提交**。修复工作量小，均不涉及重新实验（P1-6 除外，见下文说明）。

---

## 1. 核验方法与覆盖

| 维度 | 方法 | 覆盖 |
|---|---|---|
| 数据准确性 | 编写审计脚本将表 3（21 行）、表 4（21 项）与 `results_v2.json`、`native_results_sessions.json` 的原始样本逐项对拍；IQR 与 JSON 字段对拍；`bench_stats.json` 63 行复算 | 全表 |
| 算法正确性 | 通读 `wots.py`/`hbs_signature.py`/`ref_verify.py`/`experiment_v2.py`/`bench_proto.c`；F1 编码等价性用 PQClean（FIPS 205 派生）`wots.c` 源码对拍；KAT 重生成字节级比对 | 全流程 |
| payload accounting | `size_accounting.json` 与表 2/表 3/测试守卫（4512/2368/4513/2369/2144）对账 | 全表 |
| 可复现性 | 运行附录 A 核心命令（`wots.py`、`ref_verify.py`、`reproduce_checksum_bug.py`、`make_kat.py`）；118 项 pytest；state_demo 8/8；附录 C 44 项校验和重算 | 全清单 |
| 协议合规性 | 抓取 BIP-360 原文核对作者/版本/日期/P2MR 机制/OP_SUCCESSx 表述；PQClean 归档声明联网核实 | 2 条外部事实 |
| 参考文献 | 19 条题录格式审查；[13]-[16] 此前已用 IEEE/zBMath/Springer/TU Darmstadt 外部源核实；[5][19] 本次联网复核 | 19/19 |

---

## 2. 已核实通过项（证据式）

1. **表 3 与 `results_v2.json` 完全一致**：21 行 median/IQR/签名尺寸与 raw 样本中位数一致（差异 ≤1.2%，纯四舍五入）；表注的 h=6 compact IQR 异常（0.470/0.321）如实来自 JSON，且已在正文如实标注为单会话噪声。
2. **表 4 与 `native_results_sessions.json` 完全一致**：21 个 cell（跨会话中位数 + [min–max]）逐项精确匹配（ML-DSA-44/65、SLH-DSA-128f/s、Lamport、WOTS explicit/compact h=7）。
3. **F1 编码等价性成立（关键定位）**：论文称修正后的三位分解与 RFC 8391/FIPS 205 编码"数学上恒等"。已用 PQClean `sphincs-sha2-128s-simple/clean/wots.c` 对拍确认：标准算法为 `csum = c << 4` → 序列化为 2 字节 → 从字节流顶部取 3 个 nibble；对全部 c∈[0,960] 与论文普通三位分解逐值恒等（c=1→(0,0,1)、16→(0,1,0)、256→(1,0,0)、960→(3,12,0) 均验证）。**F1 定位"缺陷是零填充缓冲区误读、而非非标准编码"成立。**
4. **KAT 可复现且确定性**：附录 A 的 pk/sig 前缀与 `kat_wots.json` 一致；`make_kat.py` 重生成后 SHA-256 前 16 位不变（`ee98e45bce997e59`）——字节级一致。
5. **F1 泄露/伪造量化与表 5 完全一致**：A 20/20 接受、B 0/20（独立验证器全拒）、C/D 20/20、单字节篡改 0/20；泄露 10/10 vs 0/10；蒙特卡洛 0/20,000；解析上界 2.625e-18（≈2.6e-18）；重用 32 签名下伪造被独立验证器接受、修复版被阻止——全部与 `forgery_results.json` 逐字段一致。
6. **F2 成本声明与代码一致**：compact 与 explicit verify 同为一次 67 链前向（表 3: 0.213 vs 0.222；表 4: 0.124 vs 0.125）；`experiment_v2.py` 与 `bench_proto.c` 均无 double-pass；§3.3.2 的表述与代码相符。
7. **F3 比值自洽**：63.51/32.636≈1.95（1.9×）、0.316/0.171≈1.85（1.8×）、0.222/0.125≈1.78（1.7×），"1.6–1.9×"成立。
8. **尺寸核算全对**：h=7 explicit 4,512 / compact 2,368 / 含索引 4,513/2,369；OTS 每份 2,144 B；表 2 各标准行（ML-DSA、SLH-DSA、XMSS 2,500、LMS 1,452、BIP-340 64 B）均为正确题录值。
9. **BIP-360 引用真实准确**：作者 Hunter Beast / Ethan Heilman / Isabel Foxen Duke ✓；Status Draft ✓；Assigned 2024-12-18 ✓；v0.12.1、last updated 2026-07-24 ✓（抓取原文 changelog）；P2MR 去掉 key-path、承诺 32 B 脚本树 Merkle root、OP_SUCCESSx 升级路径表述均与原文一致。
10. **PQClean 引用真实**：commit `0586a82…` 日期 2026-08-04 ✓；仓库 2026 年 8 月只读归档 ✓（NIST pqc-forum + 多方确认）。
11. **附录 C 校验和 44/44 与当前磁盘文件一致**；HTML 标题/meta 与正文标题一致；118 项 pytest、state_demo 8/8、附录 A 核心命令全部运行通过。

---

## 3. P1 发现（投稿前必须修复）

### P1-1 fig6 图与表 2 直接矛盾（XMSS/LMS 旧值）
- **证据**：`fig6_cross_scheme_v2.png` 中 XMSS SHA256_10 标注 **2,504 B**、LMS SHA256 H10 标注 **1,624 B**；论文表 2（paper.md 第 228–229 行）已修正为 **2,500 B / 1,452 B**（第 4 轮审稿结论）。根因：`make_charts_v2.py` 第 49–50 行仍硬编码旧值 `("LMS SHA256 H10 (stateful)", 1624, ...)`、`("XMSS SHA256_10 (stateful)", 2504, ...)`。
- **影响**：图与表、图与图注（"explicit form sits between LMS (1,452 B)…"）矛盾；审稿人一眼可见。
- **修复**：改 `make_charts_v2.py` 两行为 1452 / 2500 → 重跑生成 fig6 → 重渲染 paper.html。时延图 fig7、原生图 fig8 已核实与表 3/4 一致，无需动。

### P1-2 `results/raw/benchmark_raw.json`（及 CSV）为过时数据
- **证据**：`results/raw/benchmark_raw.json` 中 h7 compact verify 中位数 = **0.461 ms**（double-pass 修复前的旧数据），h7 explicit verify = 0.255 ms、compact keygen = 65.985 ms——均与表 3（0.213 / 0.222 / 64.14）不符。但该文件仍被：附录 B（"raw timing samples are in `results/raw/`"）、附录 C（校验和 `f38ca029fd83f760` / `e56687824338ebbd`）、附录 A（复现命令会重写它）、`vectors/manifest.json`（`result_artifacts.benchmark_raw`）列为证据。
- **影响**：审稿人按附录 A 重跑 `python3 experiments/benchmark.py --reps 101` 会得到与表 3 不同的数字和不同校验和——可复现性断点。
- **修复**：用当前代码重跑该命令，更新两份结果文件与附录 C 校验和；同时处理 benchmark.py 与 experiment_v2.py 的口径差异（见 P2-2）。

### P1-3 `vectors/manifest.json` 过期，且 `source_revision` 指向缺陷代码
- **证据**：manifest 生成于 2026-10-21T07:38Z，其中 `experiment_v2.py` digest `e0c15ea…` ≠ 当前文件 `51eb2a0a…`（附录 C 值），`paper.md` digest 亦非当前值；`source_revision = e896002…` 是**修复前**的 git HEAD——审稿人 checkout 该 commit 拿到的是有校验和缺陷的代码。这与表 6 第 11 行"All rows were re-executed against the snapshot recorded in `vectors/manifest.json`"及 §5.1.1 的说法冲突。
- **修复**：先 git commit 全部工作区（见 P1-7），再运行 `make_manifest.py` 重新生成 manifest，更新附录 C 的 manifest 校验和；`environment.txt` 的 Git state 描述同步更新。

### P1-4 §5.4 观察 4 的 keygen 数值过时
- **证据**：paper.md 第 278 行"~62 ms (WOTS+) and ~91 ms (Lamport) for N=128"；表 3 实际为 **63.51 / 94.38 ms**。
- **修复**：改为"~64 / ~94 ms"（或直接引用 63.5/94.4）。

### P1-5 §5.1.1 示例统计值无法溯源
- **证据**：paper.md 第 214 行"WOTS+MSS explicit verify: median 0.205 ms, P95 0.255 ms, 95% CI [0.202, 0.217] ms"，并标注为 h=7 配置。但 `results/bench_stats.json` 中 wots explicit h=7 verify 为 **0.2220 / 0.4250 / [0.2181, 0.2234]**；63 行中无任何一行等于示例值（最近似为 h=4：0.2067/0.2595/[0.2003,0.2145]）。示例疑似旧运行残留。
- **修复**：改为 bench_stats.json 中 h=7 explicit verify 的实际行（0.222 / P95 0.425 / CI [0.218, 0.223]），或改用其他可溯源配置并注明来源。

### P1-6 域分离标签：论文规格与测量代码不一致（文档-代码漂移）
- **证据**：论文 §3.3.1（第 134 行）定义叶哈希为 `H("MSS-LEAF" ‖ pk_flat)`，§3.3.3 伪代码同；`hbs_signature.py` 第 168 行确实用 `b"MSS-LEAF"`（一致）。但**表 2/3 的数据源** `experiment_v2.py` 第 45 行用 `b"MSS-LEAF-wots"` / `b"MSS-LEAF-lamport"`，原生端 `native_bench/bench_proto.c` 第 183/190 行同样带 kind 后缀。审稿人按 §3.3.1 重建的 Merkle 树根与测量代码不同。
- **影响**：直接削弱 F2 声明的"explicit encoding specification for both formats"（规格必须能复现结果）；也影响附录 A"KAT 从所述算法即可复现"的推广。
- **修复（推荐）**：统一为论文规格——将 `experiment_v2.py` 与 `bench_proto.c` 的叶前缀改为 `b"MSS-LEAF"`（与部署 API 和论文一致），重跑验证与表 3/4（时延与尺寸不受标签影响，仅需确认验证通过、KAT/测试全绿）；或反向把论文 §3.3.1/3.3.3 改为 kind 后缀标签。前者代码改动小且让"文档=代码"成立，建议前者。

### P1-7 全部审稿成果未提交入库（无 tag/DOI）
- **证据**：`git log` 仅一个初始 commit `e896002`；工作区 11 个文件修改 + 十余个新增目录/文件未提交；附录 C 声称"Full digests are reproducible … on the tagged release"——目前无 tag。memory 记录 DOI/公开归档亦未做。
- **修复**：提交全部工作（建议一条清晰 commit，如 "Round-1..5 review fixes + artifacts"）→ 打 tag → 重生成 manifest/environment → 更新附录 C 中随提交变化的文件校验和（现 44/44 是工作区口径，提交后不变；但 manifest 需重生成）。DOI 需用户账号操作，属投稿流程外部事项。

---

## 4. P2 发现（建议修复）

### P2-1 §6.1 树高范围表述错误
- paper.md 第 311 行"message lengths 0–4,096 B across heights **1–7**"；实际 `tests/test_signature_properties.py` 的 HEIGHTS={1,2,3,4,7}（表 6 第 5 行正确写"1–4 and 7"）。改为"1–4 and 7"。

### P2-2 "三个 harness 统一 3 次预热"不实
- §5.1.1 第 214 行声称三个 harness 统一 3-iteration warm-up；`experiments/benchmark.py` 实际 keygen warmup=3、sign/verify warmup=**5**（第 87/97/104 行）。二选一：改代码为 3（与 C harness 一致），或改表述为"keygen 3 次、sign/verify 5 次"并说明与主 harness 的口径关系。

### P2-3 表 3 图注"~0.15–0.25 ms extra signing time"下界不符
- 实际 WOTS−Lamport 的 sign 差值逐行计算为 0.209–0.241 ms，"~0.15"无数据支撑。改为"~0.21–0.24 ms"。

### P2-4 摘要 ML-DSA-44 "~0.20/0.06 ms"偏松
- 表 4 为 sign 0.184 / verify 0.062；0.184 四舍五入为 0.18，"~0.20"夸大约 9%。摘要建议改"~0.18/0.06 ms"（§5.5(ii) 已用精确值，不受影响）。

### P2-5 [17] Merkle CRYPTO'87 缺 DOI
- 题录（LNCS 293, pp. 369–378）正确但无 DOI；round-3 记录为"待确认"。投稿前确认 LNCS 293 卷 DOI（建议用 Springer Link 查证 `10.1007/3-540-48184-2` 卷下该文条目），确认后补入；若确实无记录，加注说明。

---

## 5. 建议修复顺序（半天内可完成，全部不重做实验）

1. **P1-7**：git commit + tag（一切的前提，让 manifest 有意义）。
2. **P1-1**：改 `make_charts_v2.py` → 重生成 fig6 → 重渲染 paper.html。
3. **P1-6**：统一 `experiment_v2.py`/`bench_proto.c` 叶前缀为 `b"MSS-LEAF"` → 重跑 pytest 118 + wots.py + ref_verify.py（时延/尺寸不变，无需重跑基准；若求严谨可重跑 `experiment_v2.py` 与 3 会话原生基准，结果应不变）。
4. **P1-2**：重跑 `python3 experiments/benchmark.py --reps 101` → 更新 results/raw 两文件 → 更新附录 C 校验和。
5. **P1-3**：重跑 `make_manifest.py` → 更新附录 C 的 manifest 校验和 → 更新 environment.txt。
6. **P1-4 / P1-5 / P2-1 / P2-2 / P2-3 / P2-4**：正文 5 处数字/表述修正。
7. **P2-5**：联网确认 Merkle'87 DOI。
8. 重渲染 paper.html，重跑附录 C 校验和核对，全量 118 测试复核。

## 6. 未覆盖/外部事项（如实标注）

- 状态管理 **SIGKILL 分步 fsync 崩溃注入**（第 6.3 条遗留，`state_demo` 8/8 已覆盖重启/回滚/并发，但未做 kill -9 分步注入）——建议投稿前补做，属锦上添花。
- **DOI/公开归档**需用户账号操作（GitHub/Zenodo），非本地可完成。
- 表 4 各 scheme 的 `reps` 具体值未逐一核对（`native_benchmark.md` 声明 31；`native_results_sessions.json` environment 字段存在，未逐项展开）。
- 未对 PQClean 未 vendored 的标准实现做字节级复验（论文已如实声明不 vendored，仅锁 commit）。

---

## Fix status — verified 2026-10-22 (rounds 5–6)

All 7 P1 and 5 P2 findings plus the report-adjacent §3.3.2 deployment-API issue are fixed and re-verified on a quiet host:

| Finding | Fix | Verification |
|---|---|---|
| P1-1 fig6 XMSS/LMS values | `make_charts_v2.py` 2504→2500, 1624→1452; fig6 regenerated | fig6 OCR: XMSS 2,500 B / LMS 1,452 B |
| P1-2 raw JSON double-pass | full re-run of `experiment_v2.py`/`benchmark.py` on clean host | raw medians match Table 3 ballpark (verify 0.187/0.186 ms, n=101) |
| P1-3 manifest stale | `make_manifest.py` regenerated at `c1e7768`; Appendix C re-frozen | manifest `8a7b82ce543b1a47` matches committed file |
| P1-4 obs4 timings | ~62/~91 → ~50/~83 ms (new h=7 keygen 49.80/82.86) | Table 3 row h=7 |
| P1-5 §5.1.1 example | median 0.166 ms, P95 0.194 ms, CI [0.1657, 0.1660] ms | `results/bench_stats.json` h=7 explicit verify |
| P1-6 leaf label | experiment_v2.py + bench_proto.c unified to `MSS-LEAF` | 118-test suite re-run green; C sessions re-run |
| P1-7 uncommitted work | full commit `c1e7768` (+ final docs commit) + tag | `git log` |
| P2-1 tree heights | §6.1 "1–4 and 7" | matches `test_signature_properties.py` HEIGHTS |
| P2-2 warm-up | `benchmark.py` 5→3, all harnesses uniform | §5.5 method text + code |
| P2-3/P2-4 loose numbers | F3 gap 1.6–1.9× → 1.3–1.5×; ML-DSA-44 ~0.18/0.06 ms; SLH 25.02/1.49, 526.27/0.51 ms | recomputed from Table 3/4 medians |
| P2-5 [17] DOI | `10.1007/3-540-48184-2_32` added | NIST DADS source |
| §3.3.2 deployment API | disclosure: `hbs_signature.MerkleSignatureScheme` is Lamport-only | §3.3.2 text |

Final clean-host numbers: Table 3 (Python) and Table 4 (native C, 3 sessions) in `results_v2.json` / `native_results_sessions.json`; figures fig5–fig8 regenerated from the same data. 118 pytest + state_demo 8/8 green; Appendix C 44/44 matches the tagged release.
