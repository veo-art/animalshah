#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse, csv, os, sys, time, json, random, threading, datetime, glob, re
from concurrent.futures import ThreadPoolExecutor, as_completed, CancelledError
from collections import defaultdict
import requests

# --------------------------- ثابت‌ها ---------------------------
BASE_URL   = "https://iranopasmigirim.com"
ENTRY_PATH = "/fa"
DEFAULT_NEXT_ACTION   = "4053504c1d48234cc39ee65806a4592e74afd38e38"
DEFAULT_DEPLOYMENT_ID = "dpl_Hh4tYAej7Vrq8YanMCGuBxAWPnJ3"
ORIGIN  = f"{BASE_URL}"
REFERER = f"{BASE_URL}{ENTRY_PATH}"

# ------------------------- ابزارهای زمانی -----------------------
def now_utc_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def stamp():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")

def ensure_dir(d):
    os.makedirs(d, exist_ok=True)

# ----------------------- Rate Limiter ساده ----------------------
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

# ----------------------- هدرهای پایه ----------------------------
def base_headers(user_agent: str, accept_language: str):
    return {
        "User-Agent": user_agent,
        "Accept-Language": accept_language,
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
        "Origin": ORIGIN,
        "Referer": REFERER,
    }

# ---------------------- سشن Thread-Local ------------------------
_thread_local = threading.local()
def get_session(timeout_s: int, cookie_locale: str):
    """برای هر ترد یک Session جدا؛ Thread-safe."""
    if getattr(_thread_local, "session", None) is None:
        s = requests.Session()
        # کوکی زبان
        try:
            s.cookies.set("NEXT_LOCALE", cookie_locale, domain="iranopasmigirim.com", path="/")
        except Exception:
            pass
        # کانکشن پول پیش‌فرض requests برای همین Session استفاده می‌شود
        _thread_local.session = s
        _thread_local.timeout = timeout_s
    return _thread_local.session, _thread_local.timeout

# ---------------------- GET nonce و POST ------------------------
def get_x_nonce(session: requests.Session, limiter: RateLimiter, headers: dict, timeout_s: int):
    limiter.acquire()
    url = f"{BASE_URL}{ENTRY_PATH}"
    resp = session.get(url, headers={**headers, "Accept": "*/*"}, timeout=timeout_s)
    xn = resp.headers.get("x-nonce") or resp.headers.get("X-Nonce")
    return xn, resp

def post_signature(session: requests.Session, limiter: RateLimiter, headers: dict, timeout_s: int,
                   xnonce: str, payload: list, next_action: str, deployment_id: str):
    limiter.acquire()
    url = f"{BASE_URL}{ENTRY_PATH}"
    h = {
        **headers,
        "Accept": "text/x-component",
        "Content-Type": "text/plain;charset=UTF-8",
        "x-deployment-id": deployment_id,
        "next-action": next_action,
    }
    if xnonce:
        h["x-nonce"] = xnonce
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    return session.post(url, headers=h, data=data, timeout=timeout_s)

def decode_body_text(resp: requests.Response, limit=300) -> str:
    try:
        txt = resp.text or ""
        return " ".join(txt.split())[:limit]
    except Exception:
        return ""

# --------------------- امضای یک کاربر --------------------------
def sign_one(user_row, limiter, retries, timeout_s, ua, lang,
             next_action, deployment_id, require_header=None):
    name     = user_row.get("name") or ""
    sig_type = user_row.get("signatureType") or "typed"
    sig_data = user_row.get("signatureData") or name

    session, tmo = get_session(timeout_s, cookie_locale="fa")

    attempt = 0
    last_status = None
    last_headers = {}
    last_body_snip = ""
    used_nonce = None
    t_start = time.perf_counter()

    headers = base_headers(ua, lang)

    while attempt <= retries:
        attempt += 1
        try:
            # 1) GET برای nonce
            xnonce, _ = get_x_nonce(session, limiter, headers, tmo)
            used_nonce = xnonce

            # 2) POST امضا
            payload = [{
                "name": name,
                "signatureType": sig_type,
                "signatureData": sig_data
            }]
            post_resp = post_signature(session, limiter, headers, tmo, xnonce, payload, next_action, deployment_id)
            last_status = post_resp.status_code
            last_headers = dict(post_resp.headers)
            last_body_snip = decode_body_text(post_resp)

            # بررسی موفقیت
            ok_200 = 200 <= last_status < 300
            header_ok = True
            if require_header:
                header_ok = any(h.strip().lower() == require_header.strip().lower() for h in last_headers.keys())
            if ok_200 and header_ok:
                lat_ms = (time.perf_counter() - t_start) * 1000.0
                return {
                    "time": now_utc_iso(),
                    "name": name,
                    "status": last_status,
                    "ok": True,
                    "attempt": attempt,
                    "latency_ms": round(lat_ms, 2),
                    "x-nonce_used": used_nonce,
                    "response_snippet": last_body_snip,
                    "response_headers": last_headers,
                }

            # ریترای روی 429/5xx
            if last_status in (429, 500, 502, 503, 504) and attempt <= retries:
                back = min(60.0, (2 ** (attempt - 1)) + random.uniform(0.2, 0.8))
                print(f"[{name}] status={last_status} retrying in ~{back:.2f}s", flush=True)
                time.sleep(back)
                continue

            break

        except requests.RequestException as e:
            last_status = last_status or 0
            last_body_snip = f"RequestException: {e}"
            if attempt <= retries:
                back = min(60.0, (2 ** (attempt - 1)) + random.uniform(0.2, 0.8))
                print(f"[{name}] exception retrying in ~{back:.2f}s", flush=True)
                time.sleep(back)
                continue
            break

    lat_ms = (time.perf_counter() - t_start) * 1000.0
    return {
        "time": now_utc_iso(),
        "name": name,
        "status": last_status or 0,
        "ok": False,
        "attempt": attempt,
        "latency_ms": round(lat_ms, 2),
        "x-nonce_used": used_nonce,
        "response_snippet": last_body_snip,
        "response_headers": last_headers,
    }

# --------------------- اجرای یک CSV ----------------------------
def process_csv(csv_path, args):
    basename = os.path.basename(csv_path)
    base_noext = os.path.splitext(basename)[0]
    done_marker = os.path.join(args.output, f".done_{base_noext}.ok")

    if args.resume and os.path.exists(done_marker):
        print(f"[⏭] {basename} قبلاً کامل شده؛ رد شد (resume).")
        return (0, 0, defaultdict(int), 0.0)

    # بارگذاری کاربران
    users = []
    with open(csv_path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            users.append({
                "name": (row.get("name") or "").strip(),
                "signatureType": (row.get("signatureType") or "typed").strip(),
                "signatureData": (row.get("signatureData") or "").strip(),
            })
    total = len(users)
    print(f"\n🚀 اجرای فایل: {basename}")
    print(f"[+] Loaded {total} users from {basename}", flush=True)

    ensure_dir(args.output)
    sum_path = os.path.join(args.output, f"summary_{base_noext}_{stamp()}.txt")
    t0 = time.time()
    limiter = RateLimiter(args.rps)

    successes = 0
    failures  = 0
    status_counts = defaultdict(int)
    completed = 0
    lock = threading.Lock()
    interrupted = False

    # تیکرِ گزارش زنده
    stop_ticker = threading.Event()
    def ticker():
        while not stop_ticker.is_set():
            time.sleep(max(0.5, args.ticker))
            with lock:
                elapsed = max(0.001, time.time() - t0)
                print(f"[{base_noext}] prog={completed}/{total} ok={successes} fail={failures} "
                      f"avg_rps={completed/elapsed:.2f}", flush=True)

    if args.progress:
        threading.Thread(target=ticker, daemon=True).start()

    with open(sum_path, "w", encoding="utf-8") as sf:
        sf.write(f"Batch run at {stamp()}\nTotal users: {total}\n")
        try:
            with ThreadPoolExecutor(max_workers=args.workers) as ex:
                futures = {}
                for idx, u in enumerate(users, start=1):
                    fut = ex.submit(
                        sign_one, u, limiter, args.retries, args.timeout,
                        args.user_agent, args.accept_language,
                        args.next_action, args.deployment_id,
                        args.require_header
                    )
                    futures[fut] = (idx, u["name"])
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
                            "latency_ms": 0.0,
                            "x-nonce_used": None,
                            "response_snippet": f"Worker exception: {e}",
                            "response_headers": {},
                        }
                    with lock:
                        completed += 1
                        status_counts[res["status"]] += 1
                        if res["ok"]:
                            successes += 1
                        else:
                            failures += 1
                    print(f"[{idx}/{total}] {name} -> status={res['status']} ok={res['ok']}"
                          + ("" if res["ok"] else " (final)"), flush=True)
                    sf.write(json.dumps(res, ensure_ascii=False) + "\n")
                    sf.flush()
        except KeyboardInterrupt:
            interrupted = True
            print("\n[!] Interrupted — cancelling remaining tasks…", flush=True)

    stop_ticker.set()
    duration = time.time() - t0

    # فایل شکست‌ها (اختیاری)
    if args.fail_csv and failures:
        fail_path = os.path.join(args.output, f"failed_users_{base_noext}_{stamp()}.csv")
        with open(sum_path, "r", encoding="utf-8") as sf, open(fail_path, "w", newline="", encoding="utf-8") as fo:
            w = csv.writer(fo)
            w.writerow(["name"])
            for line in sf:
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict) and not obj.get("ok"):
                        w.writerow([obj.get("name","")])
                except Exception:
                    pass
        print(f"[↺] Failed CSV:     {fail_path}")

    # خلاصه‌ی نهایی همین چانک
    print("\n" + "="*50)
    print(f"[=] Completed:      {total if not interrupted else completed}" + (" (interrupted)" if interrupted else ""))
    print(f"[+] Success:        {successes}")
    print(f"[-] Failed (final): {failures}")
    print(f"[⏱] Duration:       {duration:.2f}s")
    print(f"[📝] Summary file:   {sum_path}")
    if status_counts:
        counts_str = ", ".join(f"{k}:{v}" for k,v in sorted(status_counts.items()))
        print(f"[#] Status codes:   {counts_str}")

    # مارکر اتمام برای resume
    if not interrupted:
        with open(done_marker, "w", encoding="utf-8") as dm:
            dm.write(f"{now_utc_iso()} ok={successes} fail={failures} duration={duration:.2f}s\n")

    # خروجی برای آمار کلی
    return successes, failures, status_counts, duration

# --------------------- گسترش ورودی‌ها (glob/dir/file) ----------
def expand_inputs(inp: str):
    # اگر دایرکتوری بود، همه‌ی csv داخلش
    if os.path.isdir(inp):
        files = glob.glob(os.path.join(inp, "*.csv"))
    else:
        # اگر الگو داشت ( * ? [ ] )
        if any(ch in inp for ch in "*?[]"):
            files = glob.glob(inp)
        else:
            files = [inp]
    # مرتب‌سازی طبیعی بر اساس عددِ داخل نام فایل‌ها
    def nkey(s):
        return [int(t) if t.isdigit() else t.lower() for t in re.split(r'(\d+)', os.path.basename(s))]
    return sorted(files, key=nkey)

# --------------------- main --------------------------
def main():
    ap = argparse.ArgumentParser(description="Batch signer (single or multiple CSVs) with final summary & resume")
    ap.add_argument("-i", "--input", required=True, help="فایل CSV یا الگوی glob (مثل: chunk_*.csv یا پوشه‌ای که CSV دارد)")
    ap.add_argument("-o", "--output", default="reports", help="پوشه‌ی گزارش‌ها")
    ap.add_argument("-w", "--workers", type=int, default=12, help="تعداد تردها")
    ap.add_argument("--rps", type=int, default=6, help="سقف درخواست/ثانیه (کل)")
    ap.add_argument("-r", "--retries", type=int, default=5, help="تعداد تلاش مجدد برای 429/5xx")
    ap.add_argument("--timeout", type=int, default=30, help="timeout هر درخواست (ثانیه)")
    ap.add_argument("--user-agent", default="Mozilla/5.0 (X11; Linux) AppleWebKit/537.36 (KHTML, like Gecko) Safari/537.36", help="User-Agent")
    ap.add_argument("--accept-language", default="en-US,en;q=0.9,fa;q=0.8", help="Accept-Language")
    ap.add_argument("--next-action", default=DEFAULT_NEXT_ACTION, help="next-action override (اختیاری)")
    ap.add_argument("--deployment-id", default=DEFAULT_DEPLOYMENT_ID, help="x-deployment-id override (اختیاری)")
    ap.add_argument("--require-header", default=None, help="اگر ست شود، وجود این هدر در پاسخ 200 الزامی است (مثلاً: X-Action-Revalidated)")
    ap.add_argument("--progress", action="store_true", help="گزارش دوره‌ای پیشرفت")
    ap.add_argument("--ticker", type=float, default=5.0, help="بازه‌ی گزارش زنده (ثانیه)")
    ap.add_argument("--fail-csv", action="store_true", help="خروجی CSV از اسامی ناموفق‌ها برای هر فایل")
    ap.add_argument("--resume", action="store_true", help="چانک‌های تکمیل‌شده را رد می‌کند (بر اساس فایل مارکر)")
    args = ap.parse_args()

    ensure_dir(args.output)
    files = expand_inputs(args.input)
    if not files:
        print(f"[!] هیچ فایل CSV مطابق الگو پیدا نشد: {args.input}")
        sys.exit(1)

    print(f"[+] پیدا شد: {len(files)} فایل CSV.")
    total_ok = 0
    total_fail = 0
    total_duration = 0.0
    agg_status = defaultdict(int)

    for f in files:
        ok, fail, scounts, dur = process_csv(f, args)
        total_ok += ok
        total_fail += fail
        total_duration += dur
        for k,v in scounts.items():
            agg_status[k] += v

    # جمع‌بندی کل
    print("\n" + "#"*60)
    print("[🏁] اجرای همه‌ی فایل‌ها تمام شد")
    print(f"[+] OK total:   {total_ok}")
    print(f"[-] Fail total: {total_fail}")
    if total_duration > 0:
        print(f"[⏱] Total time: {total_duration:.2f}s, avg_rps(all reqs): ~{( (total_ok+total_fail)*2 )/max(0.001,total_duration):.2f}")
    if agg_status:
        counts_str = ", ".join(f"{k}:{v}" for k,v in sorted(agg_status.items()))
        print(f"[#] Status codes (agg): {counts_str}")

if __name__ == "__main__":
    main()
