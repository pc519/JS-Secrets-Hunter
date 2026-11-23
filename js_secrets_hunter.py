import requests
import re
from urllib.parse import urljoin
from datetime import datetime
import webbrowser
import os

SECRET_PATTERNS = {
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "AWS Access Key ID": r"AKIA[0-9A-Z]{16}",
    "Stripe Live Secret Key": r"sk_live_[0-9a-zA-Z]{24}",
    "Firebase URL": r"https://[a-zA-Z0-9-]+\.firebaseio\.com",
    "Bearer / JWT Token": r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}",
    "Generic Secret / Password": r"(?i)(api_key|secret_key|password|access_token)\s*[:=]\s*['\"][a-zA-Z0-9_\-]{12,}['\"]"
}

def hunt_secrets(url):
    if not url.startswith("http"):
        url = "https://" + url
    print(f"\n[*] جاري استخراج وفحص ملفات JavaScript للموقع: {url} ...")
    headers = {"User-Agent": "Mozilla/5.0 (JS-Secrets-Hunter)"}
    
    try:
        res = requests.get(url, headers=headers, timeout=10)
    except Exception as e:
        print(f"[!] تعذر الاتصال بالموقع: {e}")
        return

    js_files = set(re.findall(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', res.text, re.I))
    print(f"[+] تم العثور على {len(js_files)} ملف JavaScript مرتبط بالصفحة.")

    findings = []
    for js_link in js_files:
        full_js_url = urljoin(url, js_link)
        try:
            js_code = requests.get(full_js_url, headers=headers, timeout=8).text
            for secret_name, pattern in SECRET_PATTERNS.items():
                matches = re.findall(pattern, js_code)
                for m in set(matches):
                    masked = m[:8] + "..." + m[-4:] if len(m) > 12 else m
                    print(f"[!] تم اكتشاف {secret_name} في {full_js_url}")
                    findings.append((secret_name, masked, full_js_url))
        except Exception:
            pass

    rows = "".join([f"<tr><td>{s_name}</td><td dir='ltr' style='color:#ef4444;font-weight:bold'>{val}</td><td dir='ltr'>{src}</td></tr>" for s_name, val, src in findings])
    if not rows:
        rows = "<tr><td colspan='3' style='text-align:center;color:#10b981'>✅ لم يتم العثور على مفاتيح API أو أسرار مكشوفة في ملفات JavaScript!</td></tr>"

    html = f"""<!DOCTYPE html>
<html lang="ar" dir="rtl"><head><meta charset="UTF-8"><title>JS Secrets Audit - {url}</title>
<style>body{{font-family:Tahoma,sans-serif;background:#0f172a;color:#f8fafc;padding:30px}}
.box{{max-width:950px;margin:auto;background:#1e293b;padding:25px;border-radius:10px}}
table{{width:100%;border-collapse:collapse;margin-top:20px}}
th,td{{padding:12px;border-bottom:1px solid #334155;text-align:right;word-break:break-all}}
th{{background:#0f172a;color:#38bdf8}}</style></head>
<body><div class="box"><h2>🔑 تقرير فحص تسريب الأسرار ومفاتيح API في ملفات JavaScript</h2>
<p><strong>الموقع:</strong> <span dir="ltr">{url}</span> | <strong>عدد ملفات JS المفحوصة:</strong> {len(js_files)}</p>
<table><tr><th>نوع المفتاح / السر</th><th>القيمة المكتشفة (مقنّعة)</th><th>الملف المصدر</th></tr>{rows}</table></div></body></html>"""

    fname = f"js_secrets_{url.replace('https://','').replace('http://','').replace('.','_').split('/')}.html"
    with open(fname, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"[+] تم حفظ التقرير: {fname}")
    webbrowser.open('file://' + os.path.realpath(fname))

if __name__ == "__main__":
    target = input("Enter website URL (e.g. github.com): ").strip()
    if target:
        hunt_secrets(target)