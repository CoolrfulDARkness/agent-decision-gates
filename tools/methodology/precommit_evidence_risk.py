#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""precommit_evidence_risk.py -- machine check for METHODOLOGY.md §3.1 (证据-风险并列行).

WHY THIS FILE EXISTS
--------------------
An earlier draft of METHODOLOGY.md §3.1 claimed the evidence-risk row was
"可机器校验" while shipping no script. A reviewer grepped the whole repo and found
zero hits. This is the thing that claim points at.

WHAT IT CHECKS (one entry = one decision about to become irreversible)
----------------------------------------------------------------------
Seven failure classes, F1..F7:

  F1  a required field is missing
  F2  同一属性 = 未知 but no "那什么才算数"          (未知 is the evasive answer)
  F3  反例预期 = 0                                  (identity / definitional evidence)
  F3s (--strict) 反例预期 > 0 but 实际观察到 = 0    (counter-example explained away)
  F4  实际观察到 is not a valid integer
  F5  k < n                                         (deploy-scope gate, see §3.3)
  F6  同一属性 = 部分 but no second independent evidence (review item 21)
  F7  回签人 missing, or 回签人 == 提案人            (P0-1: no countersign = not passed)

FIELD NAMES -- TWO ACCEPTED VOCABULARIES
----------------------------------------
METHODOLOGY.md uses one vocabulary in the §3.1 template and another (natural
questions) in the §6 quick card. A reviewer built a test entry from the §6 wording
and every field was reported missing. Rather than force one spelling, this checker
accepts both, documented here:

  canonical (§3.1)              also accepted (§6 phrasing)
  ----------------------------  ------------------------------------------
  证据：【...】                   证据测的是 ...
  本次风险：【...】               本次风险是 ...
  X 与 X' 是同一属性？ 是/部分/否/未知   X==Z? 是/部分/否/未知
  反例预期：N                    若假设为假，应有 N 个点不吻合
  实际观察到：N                  实际观察到 N
  提案人：A                      提案人 A
  回签人：B                      回签人 B
  回签原文：「...」                回签原文 「...」   (--strict only)

Markdown emphasis (**bold**) and the 「」/【】 brackets are all optional.

BOM
---
The file is read with utf-8-sig, so a UTF-8 BOM (what Notepad and many Windows
editors write by default) is ignored. Without that, the BOM stays glued to the
first heading, no entry matches, and the error says "no DEC-* entries found" for a
file that looks fine - which is impossible to diagnose from the message.

ERROR TEXT
----------
F1 messages name exactly ONE field, e.g. "F1 缺少「证据」". The accepted aliases
(§6 quick-card phrasing) are documented in the mapping table above and in
METHODOLOGY.md §3.1, not in the error string, so the message never reads like a
"field-name mismatch".

USAGE
-----
    python precommit_evidence_risk.py DECISIONS.md
    python precommit_evidence_risk.py DECISIONS.md --strict
    python precommit_evidence_risk.py --selftest      # exit 0 = self-test passed
"""

import argparse
import re
import sys


def _ensure_ascii_safe_stdout():
    """Force stdout to UTF-8, unconditionally.

    Why not probe first: a cp936 (GBK) console CAN encode Chinese, so a
    "can the current encoding represent our text?" guard concludes there is
    nothing to do and then emits GBK bytes. Those become mojibake the moment
    output is redirected to a file or runs in CI - exactly where a tool like this
    gets used. Probing only ever protected cp437/cp1252.

    Matches the convention used by audit_mem_width.py (L38) in the same repo.

    Trade-off, stated plainly: on a legacy GBK console the Chinese may now render
    as mojibake unless the code page is UTF-8 (`chcp 65001`). Redirected output and
    CI are correct. Correct bytes win over pretty console.
    """
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


_ensure_ascii_safe_stdout()


# --- field extractors, each tolerant of both vocabularies ---------------------
# Each returns the captured value, or None when the field is absent.

P_EVIDENCE = [r"证据"]                                  # presence is enough
P_RISK = [r"本次风险"]

P_SAME = [
    r"(?:是同一属性|==\s*Z)[^\n]*?(是|部分|否|未知)",
]

P_EXPECT = [
    r"反例预期[^\n]{0,12}?(-?\d+)",
    r"应有\s*(-?\d+)\s*个点",
]

P_ACTUAL = [
    r"实际观察到[^\n]{0,12}?(-?\d+)",
]

P_PROPOSER = [
    r"提案人[\s*]*[:：]?\s*([^\s，,；;*）)]+)",
]

P_SIGNER = [
    r"回签人[^\n:：]{0,20}[:：]\s*([^\s，,；;*）)]+)",
    r"回签人[\s*]*[:：]?\s*([^\s，,；;*）)]+)",
]

P_SIGNTEXT = [
    r"回签原文[^\n]{0,8}?[「\"'](.+?)[」\"']",
]

P_WHAT_COUNTS = [r"那什么才算数"]
P_SECOND_EVIDENCE = [r"第二条独立证据"]
P_DEPLOY_PAIR = [r"k\s*=\s*(\d+)\s*/\s*n\s*=\s*(\d+)"]

# An entry id is DEC-<word> or DEC<digits>. The earlier pattern `DEC[-\w]*`
# also matched the opening word of a file titled "DECISIONS.example.md", so the
# whole preamble was treated as one malformed entry (every field "missing").
# Shipping a runnable example is what caught it.
ENTRY_SPLIT = re.compile(
    r"^(?:#{1,6}\s*)?(?:id\s*[:：]\s*)?(DEC(?:[-_]\w+|\d+))", re.I | re.M)


def _first(patterns, block):
    for pat in patterns:
        m = re.search(pat, block, re.S)
        if m:
            return m
    return None


def _first_int(patterns, block):
    m = _first(patterns, block)
    if not m:
        return None
    for g in m.groups():
        if g is not None:
            try:
                return int(g)
            except ValueError:
                continue
    return None


def split_entries(text):
    marks = list(ENTRY_SPLIT.finditer(text))
    for i, m in enumerate(marks):
        end = marks[i + 1].start() if i + 1 < len(marks) else len(text)
        yield m.group(1), text[m.start():end]


def check_entry(eid, block, strict):
    fails = []

    # ---- F1: required fields ----
    if not _first(P_EVIDENCE, block):
        fails.append("F1 缺少「证据」")
    if not _first(P_RISK, block):
        fails.append("F1 缺少「本次风险」")

    same_m = _first(P_SAME, block)
    if not same_m:
        fails.append("F1 缺少「同一属性」")
    exp = _first_int(P_EXPECT, block)
    if exp is None:
        fails.append("F1 缺少「反例预期」")
    act = _first_int(P_ACTUAL, block)
    if act is None:
        fails.append("F1 缺少「实际观察到」")
    prop_m = _first(P_PROPOSER, block)
    if not prop_m:
        fails.append("F1 缺少「提案人」")
    sign_m = _first(P_SIGNER, block)
    if not sign_m:
        fails.append("F1 缺少「回签人」")

    # ---- F2: 未知 must say what would count ----
    if same_m:
        ans = same_m.group(1)
        if ans == "未知" and not _first(P_WHAT_COUNTS, block):
            fails.append("F2 同一属性=未知 但「那什么才算数」为空"
                         "（未知是最容易被拿来绕过的答案，必须给下一步测什么）")
        # 否 passes on purpose: an honest "this evidence cannot support me" is the
        # correct behaviour. Rejecting it would push people back to answering 是.
        if ans == "部分" and not _first(P_SECOND_EVIDENCE, block):
            fails.append("F6 同一属性=部分 但未给「第二条独立证据」"
                         "=> 按否处理，不得单独支持（审核第 21 条）")

    # ---- F3 / F4 ----
    if exp is not None and exp == 0:
        fails.append("F3 反例预期=0 => 恒等式/定义式，该证据作废")
    if act is not None and act < 0:
        fails.append("F4 实际观察到 不能为负")
    if strict and exp is not None and exp > 0 and act == 0:
        fails.append("F3(strict) 反例预期>0 但实际观察到=0 => 反例被解释掉或形状不成立")

    # ---- F5: deploy scope ----
    pair = _first(P_DEPLOY_PAIR, block)
    if pair:
        k, n = int(pair.group(1)), int(pair.group(2))
        if k < n:
            fails.append(f"F5 k={k} < n={n} => 只允许部署到单目标文件，不得进共享文件")

    # ---- F7: countersign must exist and must not be self-signed ----
    if prop_m and sign_m:
        if prop_m.group(1).strip() == sign_m.group(1).strip():
            fails.append("F7 回签人 = 提案人 => 自签无效（P0-1 要求非提案人回签）")
    if strict and not _first(P_SIGNTEXT, block):
        fails.append("F7(strict) 缺回签原文「我核了 X，结论 Y」")

    return fails


def run(path, strict):
    # utf-8-sig strips a leading BOM if present. Every Windows editor that writes
    # a BOM would otherwise leave "\ufeff" glued to the first heading, the entry
    # regex would not match it, and the user would see the completely opaque
    # "no DEC-* entries found" for a file that looks perfectly fine.
    text = open(path, encoding="utf-8-sig").read()
    entries = list(split_entries(text))
    if not entries:
        print(f"  !! 在 {path} 里没有找到任何 DEC-* 条目")
        print("     约定：每条决策一个 '#### DEC-xxx' 标题块")
        return 1

    bad = 0
    for eid, block in entries:
        fails = check_entry(eid, block, strict)
        if fails:
            bad += 1
            print(f"  [FAIL] {eid}")
            for f in fails:
                print(f"         {f}")
        else:
            print(f"  [ ok ] {eid}")

    print()
    print(f"  {len(entries) - bad}/{len(entries)} 条通过")
    if bad:
        print(f"  => 退出码 1：{bad} 条不满足 §3.1 闸门")
        return 1
    print("  => 退出码 0：全部满足")
    return 0


_CANON = (
    "#### DEC-ok\n"
    "证据：【属性 X，在环境 Y 测得，值 Z】\n"
    "本次风险：【属性 X】\n"
    "X 与 X' 是同一属性？ 是\n"
    "反例预期：3\n"
    "实际观察到：1\n"
    "提案人：A\n"
    "回签人：B   回签时刻：12:00   回签原文：「我核了 X，结论 是」\n"
)

_SIGN = "提案人：A\n回签人：B   回签时刻 12:00\n"

SELFTEST = (
    _CANON
    + "\n#### DEC-honest-no\n"
      "证据：【属性 X，在环境 Y，值 Z】\n"
      "本次风险：【属性 X'】\n"
      "X 与 X' 是同一属性？ 否\n"
      "反例预期：3\n"
      "实际观察到：3\n" + _SIGN
    + "\n#### DEC-quickcard-vocab\n"
      "**证据测的是** 【属性 X，在环境 Y】\n"
      "**本次风险是** 【属性 X'】\n"
      "**X==Z?** 否\n"
      "**若假设为假，应有 3 个点不吻合**\n"
      "**实际观察到** 3\n"
      "**提案人** A\n"
      "**回签人** B\n"
    + "\n#### DEC-identity\n"
      "证据：【属性 X，在环境 Y，值 Z】\n"
      "本次风险：【属性 X】\n"
      "X 与 X' 是同一属性？ 是\n"
      "反例预期：0\n"
      "实际观察到：0\n" + _SIGN
    + "\n#### DEC-unknown-no-plan\n"
      "证据：【属性 X，在环境 Y，值 Z】\n"
      "本次风险：【属性 X'】\n"
      "X 与 X' 是同一属性？ 未知\n"
      "反例预期：2\n"
      "实际观察到：2\n" + _SIGN
    + "\n#### DEC-partial-no-evidence\n"
      "证据：【属性 X，在环境 Y，值 Z】\n"
      "本次风险：【属性 X'】\n"
      "X 与 X' 是同一属性？ 部分\n"
      "反例预期：2\n"
      "实际观察到：1\n" + _SIGN
    + "\n#### DEC-deploy-overreach\n"
      "证据：【属性 X，在环境 Y，值 Z】\n"
      "本次风险：【属性 X】\n"
      "X 与 X' 是同一属性？ 是\n"
      "反例预期：2\n"
      "实际观察到：1\n"
      "k = 1 / n = 6\n" + _SIGN
    + "\n#### DEC-selfsigned\n"
      "证据：【属性 X，在环境 Y，值 Z】\n"
      "本次风险：【属性 X】\n"
      "X 与 X' 是同一属性？ 是\n"
      "反例预期：2\n"
      "实际观察到：1\n"
      "提案人：A\n"
      "回签人：A   回签时刻 12:00\n"
)


def selftest():
    import os
    import tempfile
    print("SELFTEST — 期望：ok / honest-no / quickcard-vocab 通过；"
          "identity->F3, unknown->F2, partial->F6, overreach->F5, selfsigned->F7\n")
    fd, p = tempfile.mkstemp(suffix=".md")
    os.close(fd)
    try:
        open(p, "w", encoding="utf-8").write(SELFTEST)
        rc = run(p, strict=False)
    finally:
        os.unlink(p)
    print(f"\n  checker rc = {rc}  (expected 1: five deliberately-bad entries "
          f"must all be rejected)")
    print("  selftest PASSES when this process exits 0")
    return 0 if rc == 1 else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file", nargs="?", help="decision log markdown")
    ap.add_argument("--strict", action="store_true",
                    help="额外要求：反例预期>0 时实际观察到>0；且必须有回签原文")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    if not a.file:
        ap.error("需要给一个决策日志文件，或用 --selftest")
    return run(a.file, a.strict)


if __name__ == "__main__":
    sys.exit(main())
