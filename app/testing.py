from __future__ import annotations

import argparse
import json
import time
import threading
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests


ATTACK_LABELS = {"xss", "sqli"}
MAX_WORKERS = 160

lock = threading.Lock()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()

    parser.add_argument("--dataset-root", required=True)
    parser.add_argument("--waf-url", required=True)
    parser.add_argument("--waf-log-path", required=True)
    parser.add_argument("--experiment-name", required=True,
                        choices=["hybrid","regex_only","ml_only"])

    parser.add_argument("--output-dir", default="results")

    parser.add_argument("--timeout", type=float, default=15.0)

    parser.add_argument("--log-wait-timeout",
                        type=float,
                        default=3.0)

    parser.add_argument("--truncate-waf-log",
                        action="store_true")

    parser.add_argument("--output-body-preview",
                        type=int,
                        default=300)

    return parser.parse_args()


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def derive_ground_truth(file_path: Path):

    p=str(file_path).lower()

    if "xss" in p:
        return "xss"

    if "sqli" in p:
        return "sqli"

    if "legitimate" in p:
        return "benign"

    return "benign"


def find_dataset_files(root: Path):

    return sorted(
        p for p in root.rglob("*.json")
        if p.is_file()
    )


def load_samples(f:Path):

    with f.open(encoding="utf-8") as fh:
        data=json.load(fh)

    if not isinstance(data,list):
        raise ValueError(f"{f} no es lista")

    return data


def sanitize_headers(headers):

    headers=headers or {}

    clean={}

    for k,v in headers.items():

        if v is None:
            continue

        k=str(k)

        if k.lower() in {"host","content-length"}:
            continue

        clean[k]=str(v)

    return clean


def build_target_url(base, sample):

    sample=sample or "/"

    parsed=urlsplit(sample)

    if parsed.scheme and parsed.netloc:
        return sample

    base=base.rstrip("/")+"/"

    rel=sample.lstrip("/")

    return urljoin(base,rel)


def normalize_body(data):

    if data is None:
        return None

    if isinstance(data,(dict,list)):
        return json.dumps(data,ensure_ascii=False)

    if isinstance(data,(str,bytes)):
        return data

    return str(data)


def read_new_log_entry(log_path,start_offset,timeout):

    deadline=time.time()+timeout

    current=start_offset

    while time.time()<deadline:

        if not log_path.exists():

            time.sleep(0.05)

            continue

        with log_path.open(encoding="utf-8") as f:

            f.seek(start_offset)

            chunk=f.read()

            current=f.tell()

        if chunk.strip():

            lines=[l.strip() for l in chunk.splitlines() if l.strip()]

            if lines:

                try:
                    return json.loads(lines[-1]),current

                except:

                    return None,current

        time.sleep(0.05)

    return None,current


def infer_decision(response):

    if response.status_code==403:

        try:
            payload=response.json()
            reason=payload.get("reason")

        except:
            reason=None

        return "block",reason

    h=response.headers.get("X-WAF-Decision")

    r=response.headers.get("X-WAF-Reason")

    if h:
        return h,r

    return "unknown",None


def short_text(val,limit):

    if len(val)<=limit:
        return val

    return val[:limit]+"...[TRUNCATED]"


def run_experiment(
    dataset_root,
    waf_url,
    waf_log_path,
    experiment_name,
    output_dir,
    timeout,
    log_wait_timeout,
    truncate_waf_log,
    output_body_preview
):

    dataset_files=find_dataset_files(dataset_root)

    if not dataset_files:
        raise FileNotFoundError()

    output_dir.mkdir(parents=True,exist_ok=True)

    waf_log_path.parent.mkdir(parents=True,exist_ok=True)

    if truncate_waf_log:
        waf_log_path.write_text("",encoding="utf-8")

    start_log_offset = (
        waf_log_path.stat().st_size
        if waf_log_path.exists()
        else 0
    )

    session=requests.Session()

    adapter=requests.adapters.HTTPAdapter(
        pool_connections=100,
        pool_maxsize=100
    )

    session.mount("http://",adapter)

    results=[]

    sent_total=0

    by_truth=Counter()

    by_decision=Counter()

    by_reason=Counter()

    blocked_total=0

    log_total=0

    allow_total=0

    errors_total=0

    started_at=utc_now()


    def process_sample(args):

        nonlocal sent_total
        nonlocal blocked_total
        nonlocal log_total
        nonlocal allow_total
        nonlocal errors_total
        nonlocal start_log_offset

        sample_idx,sample,ground_truth,json_file=args

        method=str(sample.get("method","GET")).upper()

        sample_url=str(sample.get("url","/"))

        headers=sanitize_headers(
            sample.get("headers")
        )

        body=normalize_body(
            sample.get("data","")
        )

        target_url=build_target_url(
            waf_url,
            sample_url
        )

        request_started=time.perf_counter()

        response_status_code=None

        response_headers={}

        response_body_preview=""

        inferred_decision="error"

        inferred_reason=None

        error_text=None

        try:

            response=session.request(
                method=method,
                url=target_url,
                headers=headers,
                data=body,
                timeout=timeout,
                allow_redirects=False
            )

            elapsed_ms=round(
                (time.perf_counter()-request_started)*1000,
                3
            )

            response_status_code=response.status_code

            response_headers=dict(response.headers)

            response_body_preview=short_text(
                response.text,
                output_body_preview
            )

            inferred_decision,inferred_reason=(
                infer_decision(response)
            )

        except Exception as exc:

            elapsed_ms=round(
                (time.perf_counter()-request_started)*1000,
                3
            )

            error_text=str(exc)

            with lock:
                errors_total+=1


        log_entry,start_log_offset=read_new_log_entry(
            waf_log_path,
            start_log_offset,
            log_wait_timeout
        )

        final_decision=None

        final_reason=None

        regex_result=None

        ml_result=None

        if log_entry:

            regex_result=log_entry.get("regex_result")

            ml_result=log_entry.get("ml_result")

            final_decision_obj=(
                log_entry.get("final_decision") or {}
            )

            final_decision=final_decision_obj.get(
                "decision"
            )

            final_reason=final_decision_obj.get(
                "reason"
            )

        decision_for_metrics=(
            final_decision or inferred_decision
        )

        reason_for_metrics=(
            final_reason or inferred_reason or "unknown"
        )

        with lock:

            sent_total+=1

            by_truth[ground_truth]+=1

            by_decision[decision_for_metrics]+=1

            by_reason[reason_for_metrics]+=1

            if decision_for_metrics=="block":
                blocked_total+=1

            elif decision_for_metrics=="log":
                log_total+=1

            elif decision_for_metrics=="allow":
                allow_total+=1


        is_attack_truth=(
            ground_truth in ATTACK_LABELS
        )

        return {

            "experiment":experiment_name,

            "timestamp_utc":utc_now(),

            "sample_id":sent_total,

            "source_file":str(json_file),

            "sample_index_in_file":sample_idx,

            "ground_truth":ground_truth,

            "ground_truth_is_attack":is_attack_truth,

            "request":{
                "method":method,
                "url":sample_url,
                "headers":headers,
                "data":body if isinstance(body,str) else str(body)
            },

            "response":{
                "status_code":response_status_code,
                "elapsed_ms":elapsed_ms,
                "headers":response_headers,
                "body_preview":response_body_preview,
                "error":error_text
            },

            "waf_observed":{
                "decision":decision_for_metrics,
                "reason":reason_for_metrics,
                "is_blocked":decision_for_metrics=="block",
                "is_logged_or_blocked":
                decision_for_metrics in {"log","block"}
            },

            "waf_log":{
                "regex_result":regex_result,
                "ml_result":ml_result,
                "final_decision":{
                    "decision":final_decision,
                    "reason":final_reason
                } if log_entry else None
            }
        }


    tasks=[]

    for json_file in dataset_files:

        ground_truth=derive_ground_truth(json_file)

        samples=load_samples(json_file)

        for sample_idx,sample in enumerate(samples):

            tasks.append(
                (sample_idx,
                 sample,
                 ground_truth,
                 json_file)
            )


    with ThreadPoolExecutor(MAX_WORKERS) as executor:

        futures=[
            executor.submit(
                process_sample,
                t
            )
            for t in tasks
        ]

        for f in as_completed(futures):

            results.append(
                f.result()
            )


    finished_at=utc_now()

    output_payload={

        "experiment":experiment_name,

        "started_at_utc":started_at,

        "finished_at_utc":finished_at,

        "summary":{

            "total_requests":sent_total,

            "truth_distribution":dict(by_truth),

            "decision_distribution":dict(by_decision),

            "reason_distribution":dict(by_reason),

            "blocked_total":blocked_total,

            "log_total":log_total,

            "allow_total":allow_total,

            "errors_total":errors_total
        },

        "results":results
    }


    output_file=(
        output_dir/
        f"results_{experiment_name}.json"
    )

    with output_file.open(
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            output_payload,
            f,
            ensure_ascii=False,
            indent=2
        )


    return output_file


def main():

    args=parse_args()

    out=run_experiment(

        dataset_root=Path(args.dataset_root),

        waf_url=args.waf_url,

        waf_log_path=Path(args.waf_log_path),

        experiment_name=args.experiment_name,

        output_dir=Path(args.output_dir),

        timeout=args.timeout,

        log_wait_timeout=args.log_wait_timeout,

        truncate_waf_log=args.truncate_waf_log,

        output_body_preview=args.output_body_preview
    )

    print(f"[OK] {out}")


if __name__=="__main__":
    main()