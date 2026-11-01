"""Cybersecurity & Threat Intelligence QA Dataset Processor and Validator.

Validates SQuAD v2 JSON datasets for rohitsroch/indic-mALBERT-squad-v2 fine-tuning,
verifying that character offsets and answer spans strictly match context strings.
Includes auto-fix and auto-alignment capabilities.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def align_and_validate_squad_v2(dataset_path: Path, auto_fix: bool = True) -> dict:
    if not dataset_path.is_file():
        raise FileNotFoundError(f"dataset file not found: {dataset_path}")

    with dataset_path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    articles = data.get("data", [])
    total_paragraphs = 0
    total_qas = 0
    total_answers = 0
    impossible_count = 0
    offset_errors = []
    fixed_count = 0

    for a_idx, article in enumerate(articles):
        paragraphs = article.get("paragraphs", [])
        total_paragraphs += len(paragraphs)
        for p_idx, p in enumerate(paragraphs):
            context = p.get("context", "")
            qas = p.get("qas", [])
            total_qas += len(qas)
            for qa in qas:
                qid = qa.get("id", "unknown")
                is_impossible = qa.get("is_impossible", False)
                if is_impossible:
                    impossible_count += 1
                answers = qa.get("answers", [])
                total_answers += len(answers)
                for ans in answers:
                    text = ans.get("text", "")
                    start = ans.get("answer_start", -1)
                    actual_start = context.find(text)
                    if actual_start == -1:
                        offset_errors.append(f"[{qid}] Answer text '{text}' not found anywhere in context")
                    elif actual_start != start:
                        if auto_fix:
                            ans["answer_start"] = actual_start
                            fixed_count += 1
                        else:
                            offset_errors.append(
                                f"[{qid}] Offset mismatch: expected {actual_start}, declared {start}"
                            )

    if auto_fix and fixed_count > 0:
        with dataset_path.open("w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    return {
        "valid": len(offset_errors) == 0,
        "fixed_count": fixed_count,
        "total_articles": len(articles),
        "total_paragraphs": total_paragraphs,
        "total_qas": total_qas,
        "total_answers": total_answers,
        "impossible_qas": impossible_count,
        "offset_errors": offset_errors,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate and align SQuAD v2 QA datasets")
    parser.add_argument(
        "--dataset",
        type=Path,
        default=Path("data/cybersecurity_threat_intel_qa.json"),
        help="Path to SQuAD v2 JSON dataset",
    )
    parser.add_argument("--no-fix", action="store_true", help="Do not auto-fix offset alignments")
    args = parser.parse_args()

    # Ensure stdout handles UTF-8 on Windows
    sys.stdout.reconfigure(encoding="utf-8")

    print(f"[*] Processing dataset: {args.dataset}")
    try:
        report = align_and_validate_squad_v2(args.dataset, auto_fix=not args.no_fix)
        print(f"[+] Total Articles     : {report['total_articles']}")
        print(f"[+] Total Paragraphs  : {report['total_paragraphs']}")
        print(f"[+] Total Q&A Pairs   : {report['total_qas']}")
        print(f"[+] Positive Answers  : {report['total_answers']}")
        print(f"[+] Impossible Queries: {report['impossible_qas']}")
        if report["fixed_count"] > 0:
            print(f"[+] Auto-aligned offsets: {report['fixed_count']} answers synchronized!")

        if report["valid"]:
            print("[+] VALIDATION PASSED: 100% of answer spans exactly match context!")
        else:
            print(f"[-] VALIDATION FAILED: {len(report['offset_errors'])} errors:")
            for err in report["offset_errors"][:10]:
                print(f"    - {err}")
            sys.exit(1)
    except Exception as exc:
        print(f"[-] Error: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
