#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Strict verdict parsing for the model responses.

Contract:
  - Reads only the API `content`; never infers the answer from `reasoning`.
    Empty content is `empty`.
  - A single label wins: the whole text, the first line, or an explicit
    answer/conclusion line.
  - With two labels, negation is resolved first ("not malicious" -> benign;
    "not benign" -> malicious). Anything still ambiguous stays `ambiguous`;
    the later label is not taken by default.
  - A refusal or filter notice is `refusal`; no label at all is `non_binary`.
  - Truncation is recorded separately from `finish_reason` by the caller and
    is not folded in here.
"""
import re

MAL = "malicious"
BEN = "benign"

# Chinese negation: 不是/并非/... (not / is not) + optional classifier + label
NEG_ZH = re.compile(
    r"(?:不是|并非|不属于|算不上|不能算|而非|绝不是|肯定不是|不可能是)"
    r"\s*(?:一个|一段|一种|个|种)?\s*(恶意|正常)"
)
NEG_EN = re.compile(r"\bnot\s+(?:a\s+|an\s+)?(malicious|benign)\b", re.I)
LABEL_ZH = re.compile(r"恶意|正常")
LABEL_EN = re.compile(r"\b(malicious|benign)\b", re.I)
EXPLICIT = re.compile(
    r"(?:最终答案|最终判断|答案|结论|判断)\s*[：:是为]?\s*(恶意|正常|malicious|benign)",
    re.I,
)
REFUSAL = re.compile(
    r"(无法(?:判断|确定|区分|给出)|不能(?:判断|确定)|抱歉|blocked by|filters|cannot (?:determine|judge|assist))",
    re.I,
)


def _norm_label(x):
    x = x.lower()
    if x in ("恶意", "malicious"):
        return MAL
    if x in ("正常", "benign"):
        return BEN
    return None


def _strip_punct(s):
    return s.strip().strip("。.!！?？：:;；,，、 \t\r\n\"'“”‘’()（）[]【】")


def _negation_aware(text):
    """Returns (verdict|None, method). Removes negated labels first and maps a
    negation to the opposite label."""
    neg_support = []  # the opposite verdict supported by each negated label
    for m in NEG_ZH.finditer(text):
        lab = _norm_label(m.group(1))
        if lab:
            neg_support.append(BEN if lab == MAL else MAL)
    for m in NEG_EN.finditer(text):
        lab = _norm_label(m.group(1))
        if lab:
            neg_support.append(BEN if lab == MAL else MAL)
    # Remove the negated fragments, then look at the labels that remain
    cleaned = NEG_ZH.sub(" ", text)
    cleaned = NEG_EN.sub(" ", cleaned)
    zh = set(LABEL_ZH.findall(cleaned))
    en = {_norm_label(x) for x in LABEL_EN.findall(cleaned)}
    remaining = set()
    if "恶意" in zh:
        remaining.add(MAL)
    if "正常" in zh:
        remaining.add(BEN)
    remaining |= en
    if len(remaining) == 1:
        return next(iter(remaining)), "negation_aware"
    # The remaining labels are still ambiguous. If the negations all point one
    # way, do not decide on that alone (it may only be rhetorical).
    if not remaining and len(set(neg_support)) == 1:
        return neg_support[0], "only_negated"
    return None, "ambiguous"


def parse_verdict(content):
    """Returns dict(status, verdict, method, excerpt). status is one of
    verdict / ambiguous / empty / refusal / non_binary."""
    raw = (content or "").strip()
    if not raw:
        return {"status": "empty", "verdict": None, "method": "empty", "excerpt": ""}
    lines = [x for x in raw.splitlines() if x.strip()]
    first = _strip_punct(lines[0]) if lines else ""
    whole = _strip_punct(raw)

    # 1) The whole text is one label
    lab = _norm_label(whole)
    if lab:
        return {"status": "verdict", "verdict": lab, "method": "exact", "excerpt": raw[:200]}

    # 2) The first line starts with, or is, one label (a trailing period is fine).
    #    If the first line carries both labels, defer to the negation/ambiguity
    #    rules so that "malicious? no, benign" is not fixed by its first word.
    if first:
        labels_in_first = set()
        if "恶意" in first:
            labels_in_first.add(MAL)
        if "正常" in first:
            labels_in_first.add(BEN)
        labels_in_first |= {_norm_label(x) for x in LABEL_EN.findall(first)}
        if len(labels_in_first) == 1:
            m = re.match(r"^(恶意|正常|malicious|benign)\b", first, re.I)
            if m:
                lab = _norm_label(m.group(1))
                if lab:
                    return {"status": "verdict", "verdict": lab, "method": "first_line", "excerpt": raw[:200]}

    # 3) An explicit answer/conclusion line; take the last one
    ms = list(EXPLICIT.finditer(raw))
    if ms:
        lab = _norm_label(ms[-1].group(1))
        if lab:
            return {"status": "verdict", "verdict": lab, "method": "explicit", "excerpt": raw[-200:]}

    # 4) Resolve negation with two labels; check negation with one as well
    has_zh = bool(LABEL_ZH.search(raw))
    has_en = bool(LABEL_EN.search(raw))
    if has_zh or has_en:
        lab, method = _negation_aware(raw)
        if lab:
            return {"status": "verdict", "verdict": lab, "method": method, "excerpt": raw[-300:]}
        if REFUSAL.search(raw):
            return {"status": "refusal", "verdict": None, "method": "refusal_with_labels", "excerpt": raw[-300:]}
        return {"status": "ambiguous", "verdict": None, "method": method, "excerpt": raw[-300:]}

    if REFUSAL.search(raw):
        return {"status": "refusal", "verdict": None, "method": "refusal", "excerpt": raw[:300]}
    return {"status": "non_binary", "verdict": None, "method": "no_label", "excerpt": raw[:300]}
