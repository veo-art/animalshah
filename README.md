# 🦊 AnimalShah — ابزار امضاگر گروهی (Batch Signer)

ابزار **AnimalShah Batch Signer** برای ارسال و امضای گروهی داده‌ها (Batch Signing) ساخته شده.  
این برنامه می‌تونه هزاران درخواست را به‌صورت خودکار، با کنترل سرعت (RPS) و ثبت گزارش کامل، ارسال کنه.

---

## ⚙️ امکانات اصلی
- 🚀 امضای خودکار هزاران یوزر در چند ترد هم‌زمان  
- 🚦 کنترل تعداد درخواست در ثانیه (`--rps`) برای جلوگیری از خطای `429`  
- 🔁 تلاش مجدد برای درخواست‌های ناموفق (`5xx` یا `429`)  
- 🧾 گزارش‌گیری دقیق از تمام امضاها در پوشه‌ی `reports/`  
- 🧮 پشتیبانی از فایل‌های CSV چندبخشی (`chunk_*.csv`)  
- 📊 گزارش نهایی با جزئیات کامل (موفق، ناموفق، زمان اجرا)

---

## 🧩 پیش‌نیازها
روی سیستم باید **Python 3.9 یا بالاتر** نصب شده باشد.  
بررسی نسخه:

```bash
python3 --version
اگر خروجی مثلاً Python 3.10.12 یا بالاتر بود، آماده‌ای ✅

🧱 مراحل نصب از صفر تا صد
🪄 1️⃣ کلون پروژه از گیت‌هاب
bash
Copy code
git clone https://github.com/veo-art/animalshah.git
cd animalshah
🧰 2️⃣ ساخت محیط مجازی (پیشنهاد می‌شود)
محیط مجازی کمک می‌کند پکیج‌ها تداخلی با سیستم نداشته باشند:

bash
Copy code
python3 -m venv .venv
source .venv/bin/activate
📦 3️⃣ نصب وابستگی‌ها (پکیج‌های لازم)
bash
Copy code
pip install requests
در صورت نیاز به کتابخانه‌های بیشتر:

bash
Copy code
pip install aiohttp
👤 4️⃣ ساخت یوزرها (فایل ورودی CSV)
برنامه برای امضا به یک فایل CSV نیاز دارد.

فایل را با نام users.csv بساز:

bash
Copy code
nano users.csv
نمونه محتوا:

csv
Copy code
name,signatureType,signatureData
User-0001,typed,Hello world
User-0002,typed,Audit test
User-0003,typed,CLI verification
User-0004,typed,Sample signing
نکته: هر خط یک یوزر جدید است. ستون اول اسم کاربر است، دومی نوع امضا (typed) و سومی داده‌ی امضا (متن دلخواه).

✂️ 5️⃣ تقسیم فایل بزرگ به تکه‌های کوچک (اختیاری)
اگر مثلاً ۱ میلیون یوزر داری، بهتر است فایل را تکه‌تکه کنی:

bash
Copy code
split -l 10000 users.csv chunk_
این دستور فایل‌های chunk_aa, chunk_ab, ... می‌سازد که هر کدام ۱۰هزار یوزر دارند.

▶️ 6️⃣ اجرای اسکریپت امضاگر
برای اجرای اصلی:

bash
Copy code
python3 batch_signer.py -i users.csv -w 12 --rps 6 -r 5 -o reports
توضیح گزینه‌ها:
گزینه	معنی
-i	مسیر فایل ورودی (CSV)
-w	تعداد تردها (کارکن‌های موازی)
--rps	حداکثر تعداد درخواست در ثانیه
-r	تعداد دفعات تلاش مجدد در خطا
-o	مسیر خروجی گزارش‌ها (پیش‌فرض reports/)

🔁 اجرای خودکار برای همه‌ی فایل‌های chunk
اگر چند فایل داری (مثل chunk_0.csv, chunk_1.csv و ...):

bash
Copy code
for f in chunk_*.csv; do
  echo "🚀 اجرای فایل $f ..."
  python3 batch_signer.py -i "$f" -w 8 --rps 4 -r 5 -o reports
done
🧾 7️⃣ بررسی وضعیت و گزارش‌ها
نمایش زنده آخرین فایل گزارش:

bash
Copy code
tail -f "$(ls -1t reports/summary_*.txt | head -n1)"
تعداد امضاهای موفق تا الان:

bash
Copy code
grep -c '"ok": true' "$(ls -1t reports/summary_*.txt | head -n1)"
نمونه خروجی خلاصه:

yaml
Copy code
==================================================
[=] Completed:       10000
[+] Success:         9870
[-] Failed (final):  130
[⏱] Duration:        190.35s
[📝] Summary file:    reports/summary_20251005_104947.txt
[✔] Final summary saved to: reports/final_summary_20251005_104948.txt
🖥️ 8️⃣ اجرای پایدار در سرور (screen mode)
اگر نمی‌خوای برنامه با قطع SSH متوقف بشه:

bash
Copy code
apt install screen -y
screen -S signer
python3 batch_signer.py -i users.csv -w 8 --rps 4 -r 5 -o reports
⏩ خروج موقت از screen:

css
Copy code
Ctrl + A سپس D
🔁 بازگشت به محیط:

bash
Copy code
screen -r signer
اگر screen مرده بود:

bash
Copy code
screen -wipe
📊 مسیر گزارش‌ها
تمام نتایج در پوشه‌ی reports/ ذخیره می‌شن:

فایل	توضیح
summary_*.txt	شامل جزئیات هر درخواست به‌صورت JSON
final_summary_*.txt	آمار نهایی و خلاصه کامل

⚠️ نکات مهم
اگر خطای 429 دیدی، مقدار --rps رو کمتر کن (مثلاً --rps 3)

اگر ModuleNotFoundError گرفتی، پکیج مربوطه رو با pip install نصب کن

هر بار اجرای برنامه، فایل گزارش جدیدی در reports/ می‌سازد

📄 مجوز
MIT License © 2025 Veo Art

💬 پشتیبانی و ارتباط
اگر سؤال یا باگی دیدی، لطفاً در بخش Issues گیت‌هاب گزارش بده:
👉 github.com/veo-art/animalshah/issues

yaml
Copy code
