#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse, csv, os, sys, time, json, random, threading, datetime
from concurrent.futures import ThreadPoolExecutor, as_completed, CancelledError
import requests

BASE_URL   = "https://iranopasmigirim.com"
ENTRY_PATH = "/fa"
DEFAULT_NEXT_ACTION   = "4053504c1d48234cc39ee65806a4592e74afd38e38"
DEFAULT_DEPLOYMENT_ID = "dpl_Hh4tYAej7Vrq8YanMCGuBxAWPnJ3"
ORIGIN  = f"{BASE_URL}"
REFERER = f"{BASE_URL}{ENTRY_PATH}"

def now_utc_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def stamp():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")

def ensure_dir(d):
    os.makedirs(d, exist_ok=True)

class RateLimiter:
    """اجازه N درخواست در ثانیه (کل). هر امضا ≈ ۲ درخواست (GET+POST)."""
    def __init__(self, rps):
        self.rps = max(1, int(rps))
        self.lock = threading.Lock()
        self.tokens = self.rps
        self.last = time.monotonic()

    def acquire(self):
        with self.lock:
            while True:
                now = time.monotonic()
                elapsed = now - self.last
                self.tokens = min(self.rps, self.tokens + elapsed * self.rps)
                self.last = now
                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return
                time.sleep(max(0.001, (1.0 - self.tokens) / self.rps))

def base_headers():
    return {
        "User-Agent": "Mozilla/5.0 (X11; Linux) AppleWebKit/537.36 (KHTML, like Gecko) Safari/537.36",
        "Accept-Language": "en-US,en;q=0.9,fa;q=0.8",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
        "Origin": ORIGIN,
        "Referer": REFERER,
    }

def get_x_nonce(session: requests.Session, limiter: RateLimiter):
    limiter.acquire()
    url = f"{BASE_URL}{ENTRY_PATH}"
    resp = session.get(url, headers={**base_headers(), "Accept": "*/*"}, timeout=30)
    xn = resp.headers.get("x-nonce") or resp.headers.get("X-Nonce")
    return xn, resp

def post_signature(session: requests.Session, limiter: RateLimiter, xnonce: str, payload: list,
                   next_action: str, deployment_id: str):
    limiter.acquire()
    url = f"{BASE_URL}{ENTRY_PATH}"
    headers = {
        **base_headers(),
        "Accept": "text/x-component",
        "Content-Type": "text/plain;charset=UTF-8",
        "x-deployment-id": deployment_id,
        "next-action": next_action,
    }
    if xnonce:
        headers["x-nonce"] = xnonce
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    return session.post(url, headers=headers, data=data, timeout=30)

def decode_body_text(resp: requests.Response) -> str:
    # requests خودش دیکامپرس می‌کند؛ همین کافیست
    try:
        txt = resp.text or ""
        return " ".join(txt.split())[:300]
    except Exception:
        return ""

def sign_one(user_row, limiter, retries, next_action, deployment_id):
    name = user_row.get("name") or ""
    sig_type = user_row.get("signatureType") or "typed"
    sig_data = user_row.get("signatureData") or name

    sess = requests.Session()
    sess.cookies.set("NEXT_LOCALE", "fa", domain="iranopasmigirim.com", path="/")

    attempt = 0
    last_status = None
    last_headers = {}
    last_body_snip = ""
    used_nonce = None

    while attempt <= retries:
        attempt += 1
        try:
            xnonce, _ = get_x_nonce(sess, limiter)
            used_nonce = xnonce

            payload = [{
                "name": name,
                "signatureType": sig_type,
                "signatureData": sig_data
            }]

            post_resp = post_signature(sess, limiter, xnonce, payload, next_action, deployment_id)
            last_status = post_resp.status_code
            last_headers = dict(post_resp.headers)
            last_body_snip = decode_body_text(post_resp)

            if 200 <= last_status < 300:
                return {
                    "time": now_utc_iso(),
                    "name": name,
                    "status": last_status,
                    "ok": True,
                    "attempt": attempt,
                    "x-nonce_used": used_nonce,
                    "response_snippet": last_body_snip,
                    "response_headers": last_headers,
                }

            if last_status in (429, 500, 502, 503, 504) and attempt <= retries:
                back = (2 ** (attempt - 1)) + random.uniform(0.2, 0.8)
                print(f"[{name}] status={last_status} retrying in ~{back:.2f}s")
                time.sleep(back)
                continue

            break

        except requests.RequestException as e:
            last_status = last_status or 0
            last_body_snip = f"RequestException: {e}"
            if attempt <= retries:
                back = (2 ** (attempt - 1)) + random.uniform(0.2, 0.8)
                print(f"[{name}] exception retrying in ~{back:.2f}s")
                time.sleep(back)
                continue
            break

    return {
        "time": now_utc_iso(),
        "name": name,
        "status": last_status or 0,
        "ok": False,
        "attempt": attempt,
        "x-nonce_used": used_nonce,
        "response_snippet": last_body_snip,
        "response_headers": last_headers,
    }

def main():
    ap = argparse.ArgumentParser(description="Batch signer with final summary")
    ap.add_argument("-i", "--input", required=True, help="CSV ورودی: name,signatureType,signatureData")
    ap.add_argument("-w", "--workers", type=int, default=12, help="تعداد تردها")
    ap.add_argument("--rps", type=int, default=6, help="سقف درخواست/ثانیه (کل)")
    ap.add_argument("-r", "--retries", type=int, default=5, help="تعداد تلاش مجدد برای 429/5xx")
    ap.add_argument("-o", "--output", default="reports", help="پوشه خروجی گزارش‌ها")
    ap.add_argument("--next-action", default=DEFAULT_NEXT_ACTION, help="next-action override (اختیاری)")
    ap.add_argument("--deployment-id", default=DEFAULT_DEPLOYMENT_ID, help="x-deployment-id override (اختیاری)")
    args = ap.parse_args()

    ensure_dir(args.output)

    users = []
    with open(args.input, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            users.append({
                "name": (row.get("name") or "").strip(),
                "signatureType": (row.get("signatureType") or "typed").strip(),
                "signatureData": (row.get("signatureData") or "").strip(),
            })

    total = len(users)
    print(f"[+] Loaded {total} users from {args.input}")

    limiter = RateLimiter(args.rps)
    t0 = time.time()

    run_results = []
    run_lock = threading.Lock()

    summary_path = os.path.join(args.output, f"summary_{stamp()}.txt")
    interrupted = False

    with open(summary_path, "w", encoding="utf-8") as summary_file:
        summary_file.write(f"Batch run at {stamp()}\nTotal users: {total}\n")

        with ThreadPoolExecutor(max_workers=args.workers) as ex:
            futures = {}
            for idx, u in enumerate(users, start=1):
                fut = ex.submit(sign_one, u, limiter, args.retries, args.next_action, args.deployment_id)
                futures[fut] = (idx, u["name"])

            try:
                for fut in as_completed(futures):
                    idx, name = futures[fut]
                    try:
                        res = fut.result()
                    except CancelledError:
                        continue
                    except Exception as e:
                        res = {
                            "time": now_utc_iso(),
                            "name": name,
                            "status": 0,
                            "ok": False,
                            "attempt": 0,
                            "x-nonce_used": None,
                            "response_snippet": f"Worker exception: {e}",
                            "response_headers": {},
                        }

                    print(f"[{idx}/{total}] {name} -> status={res['status']} ok={res['ok']}" + ("" if res["ok"] else " (final)"))
                    summary_file.write(json.dumps(res, ensure_ascii=False) + "\n")
                    summary_file.flush()
                    with run_lock:
                        run_results.append(res)

            except KeyboardInterrupt:
                print("\n[!] Interrupted — cancelling remaining tasks…")
                interrupted = True
                ex.shutdown(wait=False, cancel_futures=True)

    duration = time.time() - t0
    successes = sum(1 for r in run_results if r.get("ok"))
    failures  = sum(1 for r in run_results if not r.get("ok"))
    failed_names = [r["name"] for r in run_results if not r.get("ok")]

    print("\n" + "=" * 50)
    print(f"[=] Completed:      {total if not interrupted else len(run_results)}")
    print(f"[+] Success:        {successes}")
    print(f"[-] Failed (final): {failures}")
    print(f"[⏱] Duration:       {duration:.2f}s")
    print(f"[📝] Summary file:   {summary_path}")

    final_summary_path = os.path.join(args.output, f"final_summary_{stamp()}.txt")
    with open(final_summary_path, "w", encoding="utf-8") as fsum:
        fsum.write("=== Final Summary ===\n")
        fsum.write(f"Time: {now_utc_iso()}\n")
        fsum.write(f"Interrupted: {interrupted}\n")
        fsum.write(f"Total Planned: {total}\n")
        fsum.write(f"Completed: {len(run_results)}\n")
        fsum.write(f"Success: {successes}\nFailed(final): {failures}\n")
        fsum.write(f"Duration: {duration:.2f}s\n")
        fsum.write(f"Details file: {summary_path}\n")
        if failures:
            fsum.write("\nFailed Users:\n")
            for n in failed_names[:1000]:
                fsum.write(f"- {n}\n")

    print(f"[✔] Final summary saved to: {final_summary_path}")

if __name__ == "__main__":
    main()
