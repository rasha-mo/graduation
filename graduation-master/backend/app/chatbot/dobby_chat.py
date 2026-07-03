"""
Dobby — Smart NLP Security Assistant for Virex
================================================
No external APIs. No internet. Pure Python.

How it works:
  1. Normalize input  → strip, lowercase, remove noise
  2. Intent scoring   → each intent has a wide bank of triggers
                        (exact keywords + fuzzy similarity)
  3. Pick best intent → highest score wins
  4. Build response   → inject live dashboard data into templates
"""

import re
import os
import time
import random
import logging
import difflib
from collections import defaultdict
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

try:
    import google.generativeai as genai
    HAS_GEMINI = True
except ImportError:
    HAS_GEMINI = False

from app.chatbot.payload_analyzer import analyze_payload, generate_analysis_response, generate_payload_info


# ══════════════════════════════════════════════════════════════════
#  SECURITY SOLUTIONS KNOWLEDGE BASE (Local Fallback)
# ══════════════════════════════════════════════════════════════════

SOLUTIONS = {
    "sql_injection": {
        "title_en": "💉 SQL Injection (SQLi) Remediation Guide",
        "title_ar": "💉 دليل علاج ثغرة حقن الـ SQL (SQLi)",
        "desc_en": "SQL Injection occurs when untrusted user input is directly concatenated into SQL query strings, allowing attackers to manipulate database commands.",
        "desc_ar": "تحدث ثغرة حقن SQL عندما يتم دمج مدخلات المستخدم مباشرة مع استعلامات قاعدة البيانات، مما يسمح للمهاجم بالتلاعب بالأوامر وقراءة بيانات حساسة.",
        "steps_en": [
            "1. **Use Parameterized Queries / Prepared Statements**: Never concatenate input directly. (e.g., in SQLAlchemy, use `conn.execute(text('SELECT * FROM users WHERE id = :id'), {'id': user_id})`).",
            "2. **Use ORM Frameworks**: Use ORMs like SQLAlchemy, Django ORM, or Hibernate, which use parameterized queries automatically.",
            "3. **Principle of Least Privilege**: Ensure the database user account used by the application only has permissions necessary for its tasks (e.g., disable drop, alter database access).",
            "4. **Input Validation**: Validate and whitelist input formats (e.g., ensure an ID is strictly an integer)."
        ],
        "steps_ar": [
            "1. **استخدام الاستعلامات المجهزة (Parameterized Queries)**: لا تقم أبداً بدمج النصوص مباشرة. (مثال في SQLAlchemy: استخدم `conn.execute(text('SELECT * FROM users WHERE id = :id'), {'id': user_id})`).",
            "2. **استخدام الـ ORM**: اعتمد على إطارات العمل مثل SQLAlchemy أو Django ORM التي تقوم بحماية الاستعلامات تلقائياً.",
            "3. **مبدأ الصلاحيات الأقل**: تأكد أن مستخدم قاعدة البيانات يمتلك فقط الصلاحيات اللازمة لتشغيل التطبيق ولا يملك صلاحيات تعديل الجداول أو حذفها.",
            "4. **التحقق من المدخلات (Input Validation)**: تأكد من نوع البيانات المدخلة ومطابقتها (مثال: التأكد من أن المعرّف ID هو رقم صحيح فقط)."
        ],
        "virex_en": "Virex WAF blocks SQL Injection using **Layer 1 regex rules** (detecting UNION, SELECT, OR 1=1, comment signatures '--', '#') and **Layer 2 ML model** which detects abnormal character distributions in query parameters.",
        "virex_ar": "يقوم جدار حماية Virex بحظر هجمات حقن SQL عبر **المستوى الأول (قواعد Regex)** التي تكشف كلمات مثل UNION, SELECT, OR 1=1 وعلامات التعليق '--' و'#'، وعبر **المستوى الثاني (الذكاء الاصطناعي ML)** الذي يحلل توزيع الحروف غير الطبيعي."
    },
    "xss": {
        "title_en": "🖥️ Cross-Site Scripting (XSS) Remediation Guide",
        "title_ar": "🖥️ دليل علاج ثغرة حقن النصوص البرمجية (XSS)",
        "desc_en": "XSS allows attackers to inject malicious scripts into web pages viewed by other users, leading to cookie theft, session hijacking, or defacement.",
        "desc_ar": "تسمح ثغرة XSS للمهاجمين بحقن سكريبتات خبيثة داخل صفحات الويب التي يزورها مستخدمون آخرون، مما يؤدي لسرقة ملفات تعريف الارتباط (Cookies) أو اختراق الجلسات.",
        "steps_en": [
            "1. **HTML Entity Encoding**: Encode all untrusted output before rendering it in the browser (e.g., converting `<` to `&lt;`, `>` to `&gt;`). Flask's Jinja2 engine does this by default.",
            "2. **Implement Content Security Policy (CSP)**: Configure HTTP headers to restrict execution of scripts to trusted origins only (e.g., `Content-Security-Policy: default-src 'self'`).",
            "3. **Use Sanitization Libraries**: If rendering raw HTML, filter it using libraries like `bleach` in Python or `DOMPurify` in JavaScript.",
            "4. **HttpOnly Cookies**: Set the `HttpOnly` flag on sensitive cookies (like auth tokens) to prevent access via JavaScript `document.cookie`."
        ],
        "steps_ar": [
            "1. **ترميز مخرجات HTML (HTML Encoding)**: قم بترميز أي مخرجات غير موثوقة قبل عرضها في المتصفح. محرك Jinja2 في Flask يقوم بذلك تلقائياً بشكل افتراضي.",
            "2. **تطبيق سياسة أمان المحتوى (CSP)**: أضف ترويسة HTTP تحدد المصادر المسموح بتشغيل السكريبتات منها (مثال: `Content-Security-Policy: default-src 'self'`).",
            "3. **تنظيف المدخلات (Sanitization)**: إذا كنت مضطراً لعرض نصوص HTML، استخدم مكتبات تنظيف مثل `bleach` في بايثون أو `DOMPurify` في جافاسكريبت.",
            "4. **كوكيز آمنة (HttpOnly Cookies)**: قم بتفعيل خاصية `HttpOnly` على ملفات تعريف الارتباط الحساسة لمنع الوصول إليها عبر جافاسكريبت."
        ],
        "virex_en": "Virex WAF blocks XSS using **strict tag and handler pattern checks** (detecting `<script>`, `onerror=`, `onload=`, `javascript:`, `alert()`) and **Layer 2 ML Classifier**.",
        "virex_ar": "يحجب جدار حماية Virex ثغرات XSS باستخدام **فحص فوري للسكريبتات ومعالجات الأحداث** (مثل كشف `<script>` و`onerror=` و`onload=` و`alert()`) بالإضافة لنموذج الذكاء الاصطناعي."
    },
    "ssrf": {
        "title_en": "🌐 Server-Side Request Forgery (SSRF) Remediation Guide",
        "title_ar": "🌐 دليل علاج ثغرة تزوير الطلبات من جهة الخادم (SSRF)",
        "desc_en": "SSRF happens when a server is forced to fetch resource data from an arbitrary URL, often targeting internal services, local host ports, or cloud metadata interfaces.",
        "desc_ar": "تحدث ثغرة SSRF عندما يتم إجبار الخادم على جلب بيانات من رابط خارجي أو داخلي غير مصرح به، وغالباً ما تستهدف الخدمات الداخلية أو واجهات Cloud Metadata.",
        "steps_en": [
            "1. **Input Whitelisting**: Strictly validate and whitelist target domains/IPs that the server is allowed to fetch requests from.",
            "2. **Block Private / Loopback IPs**: Reject requests targeting private address spaces (e.g., `127.0.0.1`, `localhost`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.169.254`).",
            "3. **Disable URL Schemes**: Allow only `http` or `https`. Disable dangerous schemas like `file://`, `gopher://`, `dict://`, or `ftp://`.",
            "4. **Use Isolated Network Segments**: Deploy application servers in isolated subnets with no direct routing to sensitive internal resources."
        ],
        "steps_ar": [
            "1. **القائمة البيضاء للمواقع (Whitelisting)**: حدد بدقة النطاقات أو الـ IPs التي يسمح للخادم بالاتصال بها وجلب البيانات منها.",
            "2. **حظر العناوين المحلية والخاصة**: امنع الوصول لعناوين المضيف المحلي وIPs الشبكات المغلقة والـ Cloud Metadata (مثل `127.0.0.1`, `localhost`, `169.254.169.254`).",
            "3. **تعطيل البروتوكولات غير الضرورية**: اسمح فقط بـ `http` و `https` وعطّل البروتوكولات الخطيرة مثل `file://` و `gopher://` و `ftp://`.",
            "4. **عزل الشبكة**: ضع خادم الويب في شبكة معزولة (DMZ) تمنع الاتصال المباشر بقواعد البيانات أو الأنظمة الداخلية الحساسة."
        ],
        "virex_en": "Virex WAF defends against SSRF through **`detections/ssrf_rule.py`**, which checks outgoing link arguments for metadata services (`169.254.169.254`) and internal loopback addresses.",
        "virex_ar": "يتصدى Virex لثغرات SSRF من خلال وحدة **`detections/ssrf_rule.py`** التي تفحص متغيرات الروابط المدخلة وتمنع طلبات الـ Cloud Metadata والشبكات الخاصة."
    },
    "csrf": {
        "title_en": "🔒 Cross-Site Request Forgery (CSRF) Remediation Guide",
        "title_ar": "🔒 دليل علاج ثغرة تزوير الطلبات عبر المواقع (CSRF)",
        "desc_en": "CSRF forces an authenticated user browser to submit malicious HTTP requests (e.g., transfer funds, change password) to a vulnerable application.",
        "desc_ar": "تُجبر ثغرة CSRF متصفح المستخدم المصادق عليه على إرسال طلبات خبيثة (مثل تغيير كلمة المرور أو تحويل أموال) إلى تطبيق الويب دون علم المستخدم.",
        "steps_en": [
            "1. **Anti-CSRF Tokens**: Generate a unique, cryptographically secure token for each session. Embed it in forms/headers and validate it on POST/PUT/DELETE requests.",
            "2. **SameSite Cookie Attribute**: Set `SameSite=Lax` or `SameSite=Strict` on cookies to ensure they are not sent along with cross-site requests.",
            "3. **Validate Headers**: Check the `Origin` and `Referer` headers on incoming write requests to ensure they originate from the trusted domain.",
            "4. **Re-Authentication**: Require password entry or MFA before executing highly sensitive actions (e.g., email or password changes)."
        ],
        "steps_ar": [
            "1. **رموز مكافحة الـ CSRF**: قم بتوليد رمز تشفيري فريد وجديد لكل جلسة مستخدم، وقم بإرساله مع كل نموذج أو ترويسة وتحقق منه قبل تنفيذ العمليات الحساسة.",
            "2. **استخدام SameSite على الكوكيز**: اضبط ملفات تعريف الارتباط بقيمة `SameSite=Lax` أو `SameSite=Strict` لمنع إرسالها مع الطلبات الآتية من مواقع خارجية.",
            "3. **التحقق من ترويسات Origin و Referer**: تحقق من مصدر الطلبات القادمة للمطابقة مع النطاق الموثوق.",
            "4. **إعادة المصادقة**: اطلب إدخال كلمة المرور أو كود التحقق الثنائي قبل تغيير الإيميل أو الباسورد."
        ],
        "virex_en": "Virex WAF contains **`detections/csrf_rule.py`** which automatically monitors state-changing requests, checks authorization states, and validates the existence of anti-CSRF request attributes.",
        "virex_ar": "يتضمن Virex نظام حماية مدمج **`detections/csrf_rule.py`** يقوم بمتابعة طلبات التعديل والتحقق من رموز الـ CSRF ومطابقتها للتأكد من شرعية الطلب."
    },
    "command_injection": {
        "title_en": "💻 Command Injection Remediation Guide",
        "title_ar": "💻 دليل علاج ثغرة حقن أوامر نظام التشغيل (Command Injection)",
        "desc_en": "Command Injection occurs when user input is passed directly to system shells (e.g., `bash`, `cmd.exe`) without validation, allowing remote command execution.",
        "desc_ar": "تحدث ثغرة حقن الأوامر عندما يتم تمرير مدخلات المستخدم مباشرة لنظام التشغيل لتنفيذها كأمر (مثل `bash` أو `cmd.exe`)، مما يمنح المهاجم قدرة كاملة على السيرفر.",
        "steps_en": [
            "1. **Avoid Shell Execution APIs**: Avoid using APIs like `os.system()`, `subprocess.Popen(shell=True)`, or `eval()` in Python with user input.",
            "2. **Use Built-in APIs**: Instead of running shell commands (`ls`, `cat`), use language libraries (`os.listdir()`, `open().read()`).",
            "3. **Sanitize and Whitelist**: If shell utilities are unavoidable, use argument lists (e.g., `subprocess.run(['ping', '-c', '3', ip_address])` with `shell=False`) and strictly whitelist characters.",
            "4. **Run in Containers**: Restrict container system privileges (e.g., run as non-root user, enable read-only filesystems)."
        ],
        "steps_ar": [
            "1. **تجنب استدعاء الأوامر البرمجية المباشرة**: ابتعد عن استخدام الدوال مثل `os.system()` أو `subprocess.Popen(..., shell=True)` مع مدخلات المستخدم.",
            "2. **الاعتماد على دوال بايثون الأصلية**: بدلاً من تشغيل أمر نظام مثل `cat` أو `ls` استخدم الدوال المدمجة باللغة مثل `open().read()` و `os.listdir()`.",
            "3. **تمرير الوسائط كمصفوفة**: إذا كان تشغيل الأداة أمراً ضرورياً، مرر الوسائط كمصفوفة مع إلغاء وضع shell (مثال: `subprocess.run(['ping', '-c', '3', ip_address], shell=False)`).",
            "4. **تقييد صلاحيات الحاوية (Container)**: قم بتشغيل الحاوية بمستخدم ذو صلاحيات محدودة (Non-root) واجعل نظام الملفات للقراءة فقط."
        ],
        "virex_en": "Virex WAF intercepts Command Injection using **Layer 1 regex patterns** (detecting shell characters `;`, `|`, `&&`, `` ` ``, subshell syntax `$()`, and shell utility keywords like `rm -rf`, `nc`, `whoami`, `curl`) and **Layer 2 ML scores**.",
        "virex_ar": "يحمي Virex من حقن الأوامر عبر **قواعد Regex بالمستوى الأول** (التي ترصد الحروف الخاصة مثل `;`, `|`, `&&` وعلامات `$()` وكلمات مثل `whoami`, `nc`, `curl`, `rm -rf`) بالإضافة للذكاء الاصطناعي."
    },
    "path_traversal": {
        "title_en": "📂 Path Traversal Remediation Guide",
        "title_ar": "📂 دليل علاج ثغرة التنقل بين المسارات (Path Traversal)",
        "desc_en": "Path Traversal (or Directory Traversal) allows attackers to read arbitrary files on the server (like configuration files or credentials) by inputting relative path sequences (e.g., `../../etc/passwd`).",
        "desc_ar": "تسمح ثغرة المسارات للمهاجمين بقراءة ملفات عشوائية من الخادم (مثل ملفات الإعدادات والرموز السرية) عبر استخدام تسلسلات مسارات نسبية مثل `../../etc/passwd`.",
        "steps_en": [
            "1. **Avoid User-supplied Paths**: Avoid passing raw user input directly to file opening functions.",
            "2. **Use Path Resolution**: Resolve paths to absolute paths and verify they reside within the intended directory (e.g., using `os.path.abspath` in Python and checking the prefix).",
            "3. **Sanitize File Names**: Strip path characters using `secure_filename()` from `werkzeug.utils` before saving or retrieving files.",
            "4. **Restrict Permissions**: Configure OS file system permissions to isolate the web server directory and prevent access to `/etc/` or `System32`."
        ],
        "steps_ar": [
            "1. **تجنب مسارات المستخدم المباشرة**: لا تقم مطلقاً بتمرير نصوص المستخدم مباشرة إلى دوال فتح أو قراءة الملفات.",
            "2. **التحقق من المسار النهائي (Absolute Path)**: قم بتحويل المسار إلى مسار مطلق وتحقق من أنه يقع داخل المجلد المسموح به فقط (باستخدام `os.path.abspath` ومقارنة البداية).",
            "3. **تنظيف أسماء الملفات**: استخدم دالة `secure_filename()` من مكتبة `werkzeug.utils` لتنظيف أسماء الملفات من علامات المسارات قبل حفظها أو استدعائها.",
            "4. **تقييد صلاحيات الوصول لملفات النظام**: تأكد أن صلاحيات نظام التشغيل تعزل خادم الويب عن ملفات النظام مثل `/etc/passwd`."
        ],
        "virex_en": "Virex WAF filters Path Traversal using **Layer 1 regex rules** (blocking dot-dot-slash sequence variations like `../`, `..\\`, encoded variants `%2e%2e%2f`, and system path words like `etc/passwd`, `win.ini`, `.env`).",
        "virex_ar": "يحظر Virex ثغرة المسارات باستخدام **قواعد Regex بالمستوى الأول** (حجب علامات `../` أو `..\\` والترميز البديل لها مثل `%2e%2e%2f` والملفات الحساسة مثل `etc/passwd`, `.env`, `win.ini`)."
    },
    "brute_force": {
        "title_en": "🔑 Brute Force & Rate Limit Guide",
        "title_ar": "🔑 دليل مكافحة هجمات التخمين وضغط الطلبات",
        "desc_en": "Brute force attacks involve automated scripts submitting thousands of password combinations to steal accounts, while Rate Limit exhaustion aims to exhaust system assets (DoS).",
        "desc_ar": "تعتمد هجمات التخمين على محاولات آلية مكثفة لإدخال آلاف كلمات المرور واختراق الحسابات، بينما يسعى ضغط الطلبات إلى استنزاف موارد السيرفر وتعطيله (DoS).",
        "steps_en": [
            "1. **Account Lockout Policies**: Lock user accounts temporarily after multiple failed login attempts (e.g., 5 failures lock for 15 minutes).",
            "2. **Enable Captcha**: Render challenges (like reCAPTCHA) after multiple failed login attempts to verify the client is human.",
            "3. **Multi-Factor Authentication (MFA)**: Enforce verification codes (via email OTP, SMS, or Authenticator app).",
            "4. **Tighten Rate Limits**: Track requests by IP address and return HTTP 429 for high volume."
        ],
        "steps_ar": [
            "1. **سياسة قفل الحساب المؤقت**: قم بقفل الحساب مؤقتاً بعد عدد معين من المحاولات الخاطئة (مثال: قفل الحساب 15 دقيقة بعد 5 محاولات خاطئة).",
            "2. **تفعيل الكابتشا (CAPTCHA)**: أظهر كود كابتشا للمستخدم بعد تكرار الخطأ للتحقق من أنه إنسان وليس سكريبت آلي.",
            "3. **التحقق الثنائي (MFA/2FA)**: افترض وجود خطوة تحقق ثنائية عبر البريد الإلكتروني (OTP) أو الرسائل القصيرة.",
            "4. **تشديد حد الطلبات (Rate Limiting)**: تابع نشاط عناوين الـ IP وقم بإعطاء ترويسة HTTP 429 في حال زيادة الطلبات بشكل غير طبيعي."
        ],
        "virex_en": "Virex WAF implements **Centralized Sliding-Window Rate Limiters** and a brute force request tracker on sensitive endpoints, blocking IP ranges that trigger multiple failed actions.",
        "virex_ar": "يحتوي Virex على **نظام حد طلبات مركزي (Rate Limiting)** وسجل لرصد محاولات تسجيل الدخول الخاطئة للمهاجمين ويقوم بحظرهم آلياً."
    }
}


# ══════════════════════════════════════════════════════════════════
#  INTENT DEFINITIONS
#  Each intent has:
#    "triggers" → list of phrases/words that signal this intent
#    "lang"     → 'ar', 'en', or 'both'
# ══════════════════════════════════════════════════════════════════

INTENTS = {

    # ── Identity ──────────────────────────────────────────────────
    "identity": {
        "triggers": [
            # EN
            "who are you", "what are you", "your name", "who is dobby",
            "introduce yourself", "tell me about yourself", "what do you do",
            "are you a bot", "are you ai", "are you human", "what is your purpose",
            "how do you work", "what can you do", "your role",
            # AR
            "مين انت", "انت مين", "اسمك ايه", "عرف نفسك", "اسمك",
            "انت بتعمل ايه", "ايه دورك", "هو انت مين", "انت روبوت",
            "انت ذكاء اصطناعي", "انت بشر", "ايه وظيفتك", "بتشتغل ازاي",
        ]
    },

    # ── Greeting ──────────────────────────────────────────────────
    "greeting": {
        "triggers": [
            # EN
            "hi", "hello", "hey", "good morning", "good evening", "good afternoon",
            "howdy", "whats up", "sup", "greetings", "yo", "hiya",
            # AR
            "هاي", "هلو", "مرحبا", "السلام عليكم", "اهلا", "اهلين",
            "صباح الخير", "مساء الخير", "ازيك", "هلا", "يسلمو", "وعليكم السلام",
            "اهلا وسهلا", "هايا", "يلا هاي",
        ]
    },

    # ── How are you ───────────────────────────────────────────────
    "how_are_you": {
        "triggers": [
            # EN
            "how are you", "how are you doing", "are you okay", "you alright",
            "hows it going", "how you doing", "you good", "everything okay",
            # AR
            "عامل ايه", "ازيك", "اخبارك ايه", "كيفك", "كيف حالك",
            "عامل كويس", "انت بخير", "ايه اخبارك", "تمام",
        ]
    },

    # ── Thanks ────────────────────────────────────────────────────
    "thanks": {
        "triggers": [
            # EN
            "thank you", "thanks", "thx", "ty", "appreciate it", "great job",
            "well done", "nice", "awesome", "perfect", "good job",
            # AR
            "شكرا", "شكراً", "تسلم", "عاش", "كتر خيرك", "يسلمو",
            "شكرا جزيلا", "ممتاز", "احسنت", "برافو", "جميل",
        ]
    },

    # ── System Status ─────────────────────────────────────────────
    "system_status": {
        "triggers": [
            # EN
            "system status", "status", "overview", "health", "dashboard",
            "whats happening", "how is the system", "current state",
            "system health", "network status", "security status",
            "show stats", "give me stats", "stats",
            "summary", "report", "what is going on", "situation",
            "is the system safe", "is it safe", "are we safe",
            "under attack", "being attacked", "system secure",
            "how many attacks", "how many times attacked",
            "attacked today", "attacks today", "times attacked",
            # AR
            "الوضع ايه", "ايه الوضع", "احصائيات", "احصايات", "تقرير",
            "الحالة ايه", "ايه الحالة", "ملخص", "عرض الاحصائيات",
            "ايه اللي بيحصل", "الوضع الامني", "حالة النظام",
            "اخبار النظام", "ايه الاخبار", "اعطني احصائيات",
            "وريني الاحصائيات", "فيه ايه", "ايه في النظام",
            "عايز اعرف احوال", "احوال النظام", "النظام امن",
            "في هجمات", "بيتهاجم", "النظام بخير",
        ]
    },

    # ── SQL Injection ─────────────────────────────────────────────
    "sql_stats": {
        "triggers": [
            "sql injection attacks", "sql injection stats", "sql attacks",
            "injection attacks", "database attacks", "how many sql",
            "sql count", "sql injection attempts", "any sql injection",
            "sql statistics", "sql reports", "sql detections",
            "حقن sql", "هجمات sql", "كام sql", "اس كيو ال",
            "حقن قواعد البيانات", "هجمات قواعد البيانات",
            "كام هجمة sql",
        ]
    },

    # ── XSS ───────────────────────────────────────────────────────
    "xss_stats": {
        "triggers": [
            "cross site scripting", "script injection",
            "how many xss", "xss attacks", "xss attempts",
            "xss statistics", "xss count",
            "اكس اس اس", "كام xss", "هجمات xss",
            "حقن سكريبت", "سكريبت injection",
            "xss statistics", "xss reports", "xss detections",
        ]
    },

    # ── Brute Force ───────────────────────────────────────────────
    "brute_stats": {
        "triggers": [
            # EN
            "brute force", "brute", "login attempts", "password attacks",
            "how many brute", "failed logins", "password guessing",
            "failed login", "login failed", "wrong password",
            "password cracking", "tried to login", "tried to log in",
            # AR
            "بروت فورس", "تخمين كلمة السر", "محاولات تسجيل الدخول",
            "هجمات كلمة المرور", "كام brute", "تخمين باسورد",
            "محاولات دخول", "هجمات دخول", "حاول يخش",
            "محاولات كلمة السر", "كام واحد حاول يدخل",
        ]
    },

    # ── Scanner ───────────────────────────────────────────────────
    "scanner_stats": {
        "triggers": [
            # EN
            "scanner", "scanning", "port scan", "vulnerability scan",
            "how many scans", "reconnaissance", "recon", "probing",
            # AR
            "سكانر", "فحص", "مسح", "كام فحص", "عمليات فحص",
            "هجمات فحص", "استطلاع",
        ]
    },

    # ── Rate Limit ────────────────────────────────────────────────
    "ratelimit_stats": {
        "triggers": [
            # EN
            "rate limit", "rate limiting", "dos", "ddos",
            "too many requests", "flooding", "how many rate",
            # AR
            "rate limit", "حد الطلبات", "هجوم dos", "طوفان طلبات",
            "ضغط على السيرفر", "كام rate limit",
        ]
    },

    # ── ML Detections ─────────────────────────────────────────────
    "ml_stats": {
        "triggers": [
            # EN
            "ml detection", "machine learning", "ml", "ai detection",
            "anomaly detection", "how many ml", "ml caught", "model",
            # AR
            "كشف ml", "تعلم آلي", "الموديل", "نموذج ml",
            "كام ml", "الذكاء الاصطناعي كشف", "كشف تلقائي",
        ]
    },

    # ── Top Attacker ──────────────────────────────────────────────
    "top_attacker": {
        "triggers": [
            # EN
            "top attacker", "most attacks", "worst ip", "dangerous ip",
            "who attacked most", "top ip", "highest threat",
            "most dangerous", "repeat attacker", "most frequent",
            # AR
            "اخطر ip", "اخطر مهاجم", "اكثر هجوم", "اكتر هجوم",
            "اشد خطورة", "اي بي اخطر", "مين بيهاجم اكتر",
            "اكثر مصدر تهديد", "اخطر عنوان",
        ]
    },

    # ── Recent Threats ────────────────────────────────────────────
    "recent_threats": {
        "triggers": [
            # EN
            "recent threats", "latest threats", "last attack", "latest attack",
            "what happened", "recent events", "recent attacks",
            "show threats", "list threats", "any new attacks",
            "what was the last", "recent incidents",
            "any suspicious", "suspicious activity", "anything suspicious",
            "new threats", "show me threats", "what threats", "any attacks",
            "new attacks", "anything new", "latest events",
            # AR
            "اخر هجمة", "اخر تهديد", "ايه اخر حاجة", "اخر هجمات",
            "ايه اللي اتكشف", "التهديدات الاخيرة", "اخر الاحداث",
            "عرض التهديدات", "في هجمات حديثة", "ايه اخر واحدة",
            "في حاجة مريبة", "في نشاط غريب", "هجمات جديدة",
            "ايه الجديد", "اي هجمات", "فيه هجمات",
        ]
    },

    # ── Incident Analysis ─────────────────────────────────────────
    "incident_why": {
        "triggers": [
            # EN
            "why", "reason", "explain", "analysis",
            "analyze this", "why this", "what caused", "describe",
            "tell me about", "what is this", "details",
            "analyze threats", "analyze the threats", "analyze attacks",
            # AR
            "ليه", "سبب", "شرح", "ايه السبب", "فسرلي",
            "تحليل", "حلل", "وضحلي", "ايه ده", "تفاصيل", "حصل ايه",
            "حلل التهديدات", "حلل الهجمات", "ممكن تحلل",
        ]
    },

    # ── Incident Action ───────────────────────────────────────────
    "incident_action": {
        "triggers": [
            # EN
            "what to do", "recommended action", "how to fix", "block it",
            "should i block", "next step", "recommendation", "fix",
            "what should i do", "how to handle", "response",
            "what do i do about", "how do i handle", "deal with",
            "what should we do", "action to take", "how to respond",
            "what should i do about these threats",
            # AR
            "اعمل ايه", "ايه الحل", "كيف احل", "بلوك", "احجب",
            "نصيحتك ايه", "ايه اللي اعمله", "الخطوة الجاية",
            "كيفية التعامل", "توصية", "ازاي اتعامل",
            "ايه اللازم اعمله", "كيف اتعامل",
        ]
    },

    # ── Security Tips ─────────────────────────────────────────────
    "security_tips": {
        "triggers": [
            # EN
            "security tips", "how to improve security", "best practices",
            "recommendations", "how to protect", "security advice",
            "strengthen security", "secure the system", "improve protection",
            # AR
            "نصايح امنية", "كيف احسن الامان", "افضل ممارسات",
            "كيف احمي النظام", "توصيات امنية", "تحسين الامان",
            "نصيحة امنية", "حماية النظام",
        ]
    },

    # ── Goodbye ───────────────────────────────────────────────────
    "goodbye": {
        "triggers": [
            # EN
            "bye", "goodbye", "see you", "later", "take care",
            "cya", "farewell", "good night", "good bye",
            # AR
            "باي", "مع السلامة", "وداعا", "اشوفك", "تصبح على خير",
            "يلا باي", "سلام",
        ]
    },
    
    # ── NEW KNOWLEDGE INTENTS ─────────────────────────────────────
    "what_is_sqli": {
        "triggers": ["what is sql injection", "explain sql", "يعني ايه sql", "شرح sql", "حقن قواعد بيانات", "sqli meaning", "ما هو sql", "sql injection"]
    },
    "what_is_xss": {
        "triggers": ["what is xss", "explain xss", "cross site scripting", "يعني ايه xss", "شرح xss", "ما هو xss"]
    },
    "what_is_ddos": {
        "triggers": ["what is ddos", "explain ddos", "tell me about ddos", "dos attack", "denial of service", "يعني ايه ddos", "شرح ddos", "ما هو ddos", "حجب الخدمة", "طوفان"]
    },
    "what_is_malware": {
        "triggers": ["what is malware", "explain malware", "virus", "trojan", "ransomware", "يعني ايه فيروس", "برمجيات خبيثة", "فيروسات", "شرح malware"]
    },
    "what_is_phishing": {
        "triggers": ["what is phishing", "explain phishing", "social engineering", "يعني ايه تصيد", "شرح التصيد", "نصب", "احتيال", "phishing meaning"]
    },
    "what_is_firewall": {
        "triggers": ["what is firewall", "explain firewall", "waf", "يعني ايه جدار", "شرح جدار حماية", "ما هو الفايرول", "جدار ناري"]
    },
    "virex_info": {
        "triggers": ["what is virex", "who made virex", "virex info", "ايه هو فايركس", "مين عمل فايركس", "نظام virex", "معلومات عن virex", "فايركس"]
    },
    "dashboard_help": {
        "triggers": ["how to use", "help me", "dashboard guide", "ازاي استخدم الموقع", "شرح الموقع", "مساعدة", "استخدام الداشبورد", "لوحة التحكم", "كيف استخدم"]
    },
    "top_attack": {
        "triggers": ["top attack", "what is top attack", "most frequent attack", "highest threat", "most common attack", "اكتر هجوم متكرر", "اخطر نوع هجوم", "اكثر هجوم", "نوع الهجوم المنتشر", "top attack type"]
    },
    "analyze_payload": {
        "triggers": [
            "analyze this", "حلل ده", "حلل دا", "حلل", "analyze",
            "what is this attack", "ايه الهجوم ده", "ايه ده",
            "what attack is this", "analyse", "check this",
            "look at this", "شوف ده", "كشف", "كشّف",
            "detect", "اكتشف", "اختبر",
        ]
    },
    "follow_up": {
        "triggers": [
            "tell me more", "more", "come on", "yes tell me", "ok go on",
            "continue", "keep going", "go on", "what else",
            "tell me about it", "i wanna know more", "expand",
            "اكمل", "عايز اعرف اكتر", "قول تاني", "كمل", "ايوه",
            "و", "هقولك", "طب قولي", "زياده", "تفاصيل اكتر",
            "عايز تفاصيل", "هات الباقي", "ايه كمان", "بعدين",
            "حلو", "كده كده", "ايوه طبعا", "ايوه قولي",
            "يدخل في تفاصيل", "تفصيل", "more details",
            "what about it", "what about", "how so",
        ]
    },
}

# --- EXTENDED EXISTING INTENTS FOR BETTER RECOGNITION ---
INTENTS["greeting"]["triggers"].extend(["عامل ايه يا دوبي", "يا دوبي", "صباحو", "مساءو", "hello dobby", "hi dobby", "ازيك يا دوبي"])
INTENTS["system_status"]["triggers"].extend(["طمني", "كله تمام", "في هجمات دلوقتي", "اي الاخبار", "كله في السليم", "حالة السيرفر"])
INTENTS["thanks"]["triggers"].extend(["حبيبي", "كفاءة", "الله ينور", "تسلم ايدك", "شكرا يا دوبي", "عظمة"])
INTENTS["identity"]["triggers"].extend(["انت مين يالا", "مين المطور بتاعك", "مين برمجك", "انت عبارة عن ايه", "عرفني عليك"])
INTENTS["top_attacker"]["triggers"].extend(["مين اكتر حد بيهاجم", "اسوا اي بي", "مين بيبعت هجمات", "اخطر حد"])
INTENTS["recent_threats"]["triggers"].extend(["حصل ايه من شوية", "اخر الاخبار", "شوف كده في هجمات", "اخر تهديدات", "ايه بيحصل"])

INTENTS["incident_action"]["triggers"].extend(["تنصحني بايه", "اتصرف ازاي", "اعمل ايه مع الهجوم", "الحل ايه"])



def _normalize(text: str) -> str:
    """Lowercase, remove punctuation, normalize Arabic chars."""
    text = text.lower().strip()
    # Remove common punctuation
    text = re.sub(r'[؟?!.,،;:\-_"\'()]', ' ', text)
    # Normalize Arabic alef variants
    text = re.sub(r'[أإآا]', 'ا', text)
    # Normalize teh marbuta
    text = re.sub(r'ة', 'ه', text)
    # Collapse whitespace
    text = re.sub(r'\s+', ' ', text).strip()
    return text


STOP_WORDS = {"is", "are", "do", "does", "what", "how", "who", "tell", "me", "about", "can", "you", "the", "a", "an", "في", "ايه", "هو", "مين", "عن", "من", "هل", "بتاع", "يعني", "شرح", "وضح", "قولي"}

def _stem(word: str) -> str:
    if word.endswith('s') and len(word) > 3 and not word.endswith('ss'):
        return word[:-1]
    return word

def _intent_score(query_norm: str, triggers: list) -> float:
    """
    Score how well query matches this intent.
    Combines:
      - exact substring match  (weight 1.0)
      - token-level match      (weight 0.8)
      - fuzzy similarity       (weight 0.6)
    Returns score 0.0 → 1.0
    """
    best = 0.0
    
    raw_q_tokens = query_norm.split()
    q_tokens = { _stem(w) for w in raw_q_tokens if w not in STOP_WORDS }

    for trigger in triggers:
        t_norm = _normalize(trigger)
        raw_t_tokens = t_norm.split()
        t_tokens = { _stem(w) for w in raw_t_tokens if w not in STOP_WORDS }

        # Exact word-boundary match (prevents "hi" matching inside "something")
        if re.search(r'\b' + re.escape(t_norm) + r'\b', query_norm) or \
           re.search(r'\b' + re.escape(query_norm) + r'\b', t_norm):
            best = max(best, 1.0)
            continue

        # Token overlap ratio
        if t_tokens and q_tokens:
            overlap = len(q_tokens & t_tokens) / max(len(t_tokens), 1)
            # Boost score significantly if ALL non-stop tokens of the trigger are in the query
            if len(q_tokens & t_tokens) == len(t_tokens):
                best = max(best, 0.95)
            else:
                best = max(best, overlap * 0.85)

        # Fuzzy similarity on full string
        ratio = difflib.SequenceMatcher(None, query_norm, t_norm).ratio()
        best = max(best, ratio * 0.7)

    return best


def _classify(query: str, threshold: float = 0.50) -> str:
    """Return the best-matching intent name, or 'unknown'."""
    q_norm = _normalize(query)
    scores = {}
    for intent_name, intent_data in INTENTS.items():
        scores[intent_name] = _intent_score(q_norm, intent_data["triggers"])

    best_score = max(scores.values(), default=0)
    if best_score < threshold:
        return "unknown"

    # Break ties: prefer more specific intent
    knowledge_priority = {"what_is_sqli", "what_is_xss", "what_is_ddos",
                          "what_is_malware", "what_is_phishing", "what_is_firewall",
                          "virex_info"}
    ties = [n for n, s in scores.items() if s == best_score]
    if len(ties) > 1:
        # 1) prefer knowledge/explain intents
        for t in ties:
            if t in knowledge_priority:
                return t
        # 2) prefer intents whose trigger is a longer substring match
        best_len = 0
        best_intent = ties[0]
        for t in ties:
            for trigger in INTENTS[t]["triggers"]:
                t_norm = _normalize(trigger)
                if re.search(r'\b' + re.escape(t_norm) + r'\b', q_norm):
                    if len(t_norm) > best_len:
                        best_len = len(t_norm)
                        best_intent = t
        if best_len > 0:
            return best_intent
    return ties[0]


# ══════════════════════════════════════════════════════════════════
#  CHATBOT CLASS
# ══════════════════════════════════════════════════════════════════

class SecurityChatbot:
    """
    Dobby — Smart NLP Security Assistant.
    Uses intent classification + fuzzy matching.
    No external APIs required.
    """

    def __init__(self, dashboard_ref):
        self.dashboard = dashboard_ref
        try:
            # Try new structure first
            from app.auth.roles import Role
            self.Role = Role
        except ImportError:
            # Fallback to root structure
            from roles import Role
            self.Role = Role

    # ── Language Detection ────────────────────────────────────────
    def _lang(self, text: str) -> str:
        return 'ar' if any('\u0600' <= c <= '\u06FF' for c in text) else 'en'

    # ── Response Builders ─────────────────────────────────────────

    def _r_identity(self, lang):
        if lang == 'ar':
            return random.choice([
                "أنا **Dobby** 🛡️ — مساعدك الأمني في Virex.\nبحلل الهجمات، بديك إحصائيات، وبساعدك تاخد القرار الصح.",
                "اسمي **Dobby**، المساعد الأمني الخاص بنظام Virex.\nاسألني عن أي هجمة أو تهديد وهرد عليك.",
                "معاك **Dobby** من Virex 🛡️\nاقدر أحلل التهديدات، أعطيك إحصائيات مباشرة، وأوصيك بالخطوات الصح.",
            ])
        return random.choice([
            "I'm **Dobby** 🛡️ — Virex's Security Assistant.\nI analyze threats, provide live stats, and help you make the right call.",
            "Name's **Dobby**. I'm the security assistant built into Virex.\nAsk me anything about attacks, incidents, or system health.",
            "Hey! I'm **Dobby**, your Virex security companion 🛡️\nI can analyze threats, show stats, and guide your response.",
        ])

    def _r_greeting(self, lang):
        if lang == 'ar':
            return random.choice([
                "أهلاً! 👋 معاك Dobby. إيه اللي تحب تعرفه عن النظام؟",
                "يا هلا! أنا Dobby جاهز. اسألني عن أي تهديد أو هجمة. 🛡️",
                "مرحباً بيك! 👋 Dobby في الخدمة. إيه اللي تحتاجه؟",
            ])
        return random.choice([
            "Hey there! 👋 Dobby here. What would you like to know about the system?",
            "Hello! I'm Dobby, ready to help. Ask me about any threat or attack. 🛡️",
            "Hi! Dobby at your service 👋 What can I help you with?",
        ])

    def _r_how_are_you(self, lang):
        s = self.dashboard.stats
        if lang == 'ar':
            return f"أنا تمام، والنظام شغال! 💪\nحالياً بتابع **{s.get('total_requests',0)}** طلب وحجبت **{s.get('blocked_requests',0)}** هجمة."
        return f"All good, system is running! 💪\nCurrently monitoring **{s.get('total_requests',0)}** requests with **{s.get('blocked_requests',0)}** blocked."

    def _r_thanks(self, lang):
        if lang == 'ar':
            return random.choice([
                "العفو! 🫡 أنا دايماً في الخدمة.",
                "يسعدني! لو في أي حاجة تانية قولي. 👍",
                "زي الفل! عرفني لو احتجت حاجة. 🛡️",
            ])
        return random.choice([
            "You're welcome! 🫡 Always here to help.",
            "Happy to help! Let me know if you need anything else. 👍",
            "Anytime! Stay secure. 🛡️",
        ])

    def _r_status(self, lang):
        s = self.dashboard.stats
        blocked_pct = 0
        if s.get('total_requests', 0) > 0:
            blocked_pct = round(s['blocked_requests'] / s['total_requests'] * 100, 1)

        if lang == 'ar':
            return (
                f"**📊 تقرير حالة النظام:**\n\n"
                f"🔵 إجمالي الطلبات : **{s.get('total_requests',0)}**\n"
                f"🔴 محجوب           : **{s.get('blocked_requests',0)}** ({blocked_pct}%)\n"
                f"🤖 كشف ML          : **{s.get('ml_detections',0)}**\n"
                f"💉 SQL Injection    : **{s.get('sql_injection_attempts',0)}**\n"
                f"🖥️ XSS             : **{s.get('xss_attempts',0)}**\n"
                f"🔑 Brute Force      : **{s.get('brute_force_attempts',0)}**\n"
                f"🔍 Scanner          : **{s.get('scanner_attempts',0)}**\n"
                f"⏱️ Rate Limit       : **{s.get('rate_limit_hits',0)}**"
            )
        return (
            f"**📊 System Status Report:**\n\n"
            f"🔵 Total Requests : **{s.get('total_requests',0)}**\n"
            f"🔴 Blocked        : **{s.get('blocked_requests',0)}** ({blocked_pct}%)\n"
            f"🤖 ML Detections  : **{s.get('ml_detections',0)}**\n"
            f"💉 SQL Injection   : **{s.get('sql_injection_attempts',0)}**\n"
            f"🖥️ XSS            : **{s.get('xss_attempts',0)}**\n"
            f"🔑 Brute Force     : **{s.get('brute_force_attempts',0)}**\n"
            f"🔍 Scanner         : **{s.get('scanner_attempts',0)}**\n"
            f"⏱️ Rate Limit      : **{s.get('rate_limit_hits',0)}**"
        )

    def _r_attack_stat(self, intent, lang):
        s = self.dashboard.stats
        mapping = {
            "sql_stats":      (s.get('sql_injection_attempts', 0), "SQL Injection",        "حقن SQL"),
            "xss_stats":      (s.get('xss_attempts', 0),           "XSS",                  "XSS"),
            "brute_stats":    (s.get('brute_force_attempts', 0),    "Brute Force",          "Brute Force"),
            "scanner_stats":  (s.get('scanner_attempts', 0),        "Scanner",              "فحص"),
            "ratelimit_stats":(s.get('rate_limit_hits', 0),         "Rate Limit",           "Rate Limit"),
            "ml_stats":       (s.get('ml_detections', 0),           "ML Anomaly Detection", "كشف ML"),
        }
        count, name_en, name_ar = mapping[intent]
        if lang == 'ar':
            return f"🛡️ رصدنا **{count}** محاولة {name_ar} لحد دلوقتي."
        return f"🛡️ Detected **{count}** {name_en} attempts so far."

    def _r_top_attacker(self, lang, is_admin):
        top = self.dashboard.get_top_attackers(3)
        if not top:
            return ("لسه مفيش هجمات مسجلة. 🟢" if lang == 'ar'
                    else "No attacks recorded yet. 🟢")
        lines = []
        for i, (ip, count) in enumerate(top, 1):
            ip_d = ip if is_admin else "XXX.XXX.XXX.XXX"
            lines.append(f"{i}. `{ip_d}` — **{count}** محاولة" if lang == 'ar'
                         else f"{i}. `{ip_d}` — **{count}** attempts")
        header = "🚨 **أخطر المصادر:**\n" if lang == 'ar' else "🚨 **Top Attackers:**\n"
        return header + "\n".join(lines)

    def _r_top_attack(self, lang):
        s = self.dashboard.stats
        attack_types = {
            "SQL Injection": s.get('sql_injection_attempts', 0),
            "XSS": s.get('xss_attempts', 0),
            "Brute Force": s.get('brute_force_attempts', 0),
            "Scanner": s.get('scanner_attempts', 0),
            "Rate Limit/DDoS": s.get('rate_limit_hits', 0),
        }
        if not attack_types or all(v == 0 for v in attack_types.values()):
            return ("لاتوجد هجمات حالياً. النظام آمن! 🟢" if lang == 'ar'
                    else "No attacks recorded currently. System is safe! 🟢")
            
        top_name, top_count = max(attack_types.items(), key=lambda x: x[1])
        if lang == 'ar':
            return f"🚨 **أعلى نوع هجوم (Top Attack):**\nهو **{top_name}** بعدد `{top_count}` محاولة."
        return f"🚨 **Top Attack Type:**\nIt is **{top_name}** with `{top_count}` attempts."

    def _r_recent_threats(self, lang, is_admin):
        recent = list(self.dashboard.recent_threats)[-5:]
        if not recent:
            return ("مفيش تهديدات حديثة. 🟢" if lang == 'ar'
                    else "No recent threats. 🟢")
        header = "🔥 **آخر التهديدات:**\n" if lang == 'ar' else "🔥 **Recent Threats:**\n"
        lines = []
        for t in reversed(recent):
            ip_d = t.get('ip', '?') if is_admin else "XXX.XXX.XXX.XXX"
            lines.append(
                f"• `{t.get('timestamp','?')}` — **{t.get('type','?')}** "
                f"من {ip_d} ({t.get('severity','?')})"
                if lang == 'ar' else
                f"• `{t.get('timestamp','?')}` — **{t.get('type','?')}** "
                f"from {ip_d} ({t.get('severity','?')})"
            )
        return header + "\n".join(lines)

    def _r_security_tips(self, lang):
        if lang == 'ar':
            return (
                "**💡 نصايح أمنية عامة:**\n\n"
                "1. 🔒 غيّر الـ passwords الافتراضية فوراً\n"
                "2. 🛡️ فعّل الـ Rate Limiting على كل الـ endpoints\n"
                "3. 📋 راجع الـ logs بشكل دوري\n"
                "4. 🚫 اعمل block للـ IPs اللي بتهاجم بشكل متكرر\n"
                "5. 🔄 حدّث الـ ML model بانتظام على بيانات جديدة\n"
                "6. ⚡ فعّل التنبيهات الفورية للهجمات الحرجة"
            )
        return (
            "**💡 Security Best Practices:**\n\n"
            "1. 🔒 Change all default passwords immediately\n"
            "2. 🛡️ Enable Rate Limiting on all endpoints\n"
            "3. 📋 Review logs regularly\n"
            "4. 🚫 Block IPs with repeated attack attempts\n"
            "5. 🔄 Retrain the ML model with fresh data periodically\n"
            "6. ⚡ Enable real-time alerts for critical attacks"
        )

    def _r_incident_why(self, inc, lang, is_admin):
        ip_d = inc.source_ip if is_admin else "XXX.XXX.XXX.XXX"
        payload_d = (inc.events[0].get('snippet', '')[:40] if is_admin else "[HIDDEN]") if inc.events else "N/A"
        if lang == 'ar':
            return (
                f"**🔍 تحليل الحادثة:**\n\n"
                f"• النوع      : **{inc.category}**\n"
                f"• المصدر     : `{ip_d}`\n"
                f"• الخطورة    : **{inc.severity}**\n"
                f"• الحالة     : {inc.status}\n"
                f"• Payload    : `{payload_d}`\n\n"
                f"ده غالباً هجوم بيحاول يستغل ثغرة في النظام. "
                f"عدد المحاولات: **{len(inc.events)}**."
            )
        return (
            f"**🔍 Incident Analysis:**\n\n"
            f"• Type     : **{inc.category}**\n"
            f"• Source   : `{ip_d}`\n"
            f"• Severity : **{inc.severity}**\n"
            f"• Status   : {inc.status}\n"
            f"• Payload  : `{payload_d}`\n\n"
            f"This is likely an exploit attempt targeting a system vulnerability. "
            f"Total attempts: **{len(inc.events)}**."
        )

    def _r_incident_action(self, inc, lang, is_admin):
        ip_d = inc.source_ip if is_admin else "هذا المصدر"
        if lang == 'ar':
            return (
                f"**⚡ توصيات Dobby:**\n\n"
                f"1. **احجب {ip_d}** فوراً من صفحة الـ Incidents\n"
                f"2. راجع سجلات السيرفر للتأكد مفيش حاجة اتسربت\n"
                f"3. لو كانت False Positive، سجلها وأغلق الحادثة\n"
                f"4. لو الهجوم مستمر، فعّل Rate Limiting أقوى\n"
                f"5. حدّث الـ ML model لو النمع ده جديد"
            )
        ip_d = inc.source_ip if is_admin else "this source"
        return (
            f"**⚡ Dobby Recommendations:**\n\n"
            f"1. **Block {ip_d}** immediately from the Incidents page\n"
            f"2. Review server logs to confirm no data was breached\n"
            f"3. If it's a False Positive, mark and close the incident\n"
            f"4. If attacks persist, tighten Rate Limiting\n"
            f"5. Retrain the ML model if this is a new attack pattern"
        )

    def _r_goodbye(self, lang):
        if lang == 'ar':
            return random.choice([
                "مع السلامة! 👋 Dobby دايماً هنا لو احتجت.",
                "باي! 🛡️ النظام تحت المراقبة.",
                "تصبح على خير! Dobby يراقب كل حاجة. 😎",
            ])
        return random.choice([
            "Goodbye! 👋 Dobby is always here if you need.",
            "See you! 🛡️ System stays monitored.",
            "Take care! Dobby keeps watching. 😎",
        ])

    def _r_what_is_sqli(self, lang):
        if lang == 'ar':
            return random.choice([
                "**حقن قواعد البيانات (SQL Injection):**\nهو هجوم بيستغل ثغرات في الكود عشان ينفذ أوامر SQL خبيثة جوه قاعدة البيانات. المهاجم ممكن يسرق بيانات، يمسحها، أو حتى يتحكم في السيرفر!",
                "**SQLi:**\nبيحط المهاجم أوامر SQL جوه المدخلات (زي username أو id) ولو الكود مش مؤمن، الأوامر دي تتنفذ على الداتابيز. مثلاً: `' OR 1=1 --` تخليه يدخل من غير باسورد.",
                "**SQL Injection:**\nثغرة خطيرة جداً 🔴. لو مهاجم قدر يحقن `DROP TABLE`، ممكن يمسح قاعدة البيانات كلها. الحل: استخدم prepared statements دايمًا ومتسبش user input يتنفذ كـ SQL.",
            ])
        return random.choice([
            "**SQL Injection (SQLi):**\nAn attack that executes malicious SQL statements to manipulate database data, allowing attackers to view, modify, or delete restricted information.",
            "**How SQLi works:**\nAttackers inject SQL code into input fields (like login forms). If unsanitized, the DB runs it. Example: `' OR 1=1 --` bypasses authentication entirely.",
            "**SQLi Risk:** 🔴 Critical. An attacker can `SELECT` passwords, `DROP` tables, or `UPDATE` privileges. **Prevention:** Use parameterized queries / prepared statements. Never trust user input.",
        ])

    def _r_what_is_xss(self, lang):
        if lang == 'ar':
            return random.choice([
                "**السكربتات العابرة للمواقع (XSS):**\nالمهاجم بيحط كود خبيث (زي جافاسكريبت) جوه صفحة ويب بيشوفها مستخدمين تانيين. ده بيسمحله يسرق الكوكيز أو يغير شكل الصفحة!",
                "**XSS:**\nنوعين أساسيين:\n• **Stored XSS**: الكود بيتخزن في السيرفر (زي تعليق) وكل ما حد يفتح الصفحة يتنفذ.\n• **Reflected XSS**: الكود بيتنفذ مرة واحدة (زي لينك مريبة).",
                "**XSS Risk:** 🟠 High. المهاجم يسرق session cookies، يعمل redirect لمواقع ضارة، أو يغير محتوى الموقع. الحل: دايماً sanitize الـ HTML output.",
            ])
        return random.choice([
            "**Cross-Site Scripting (XSS):**\nA vulnerability where an attacker injects malicious scripts into trusted websites viewed by other users, often used to steal session cookies.",
            "**XSS Types:**\n• **Stored**: Malicious script saved on server (e.g., in a comment). Executes for every visitor.\n• **Reflected**: Script in a URL that executes once. Delivered via phishing links.",
            "**XSS Risk:** 🟠 High. Attackers can hijack sessions, deface pages, or redirect users. **Prevention:** Sanitize all user-generated HTML output, use Content-Security-Policy headers.",
        ])

    def _r_what_is_ddos(self, lang):
        if lang == 'ar':
            return random.choice([
                "**هجوم حجب الخدمة (DDoS):**\nالمهاجم بيبعت آلاف أو ملايين الطلبات الوهمية للسيرفر في نفس الوقت، عشان يخليه يقع أو يبطأ جداً وميقدرش يخدم المستخدمين الحقيقيين.",
                "**DDoS:**\nالفرق بين DoS و DDoS:\n• **DoS**: من جهاز واحد.\n• **DDoS**: من آلاف الأجهزة (botnet) — أصعب في الصد.",
                "**DDoS Risk:** 🟠 High. ممكن يوقف الموقع بالكامل. الحل: استخدم Rate Limiting، CDN (Cloudflare)، وأضف الـ IPs المشبوهة إلى القائمة السوداء.",
            ])
        return random.choice([
            "**Distributed Denial of Service (DDoS):**\nA malicious attempt to disrupt normal traffic of a targeted server by overwhelming it with a flood of internet traffic.",
            "**DoS vs DDoS:**\n• **DoS**: Single source, easier to block.\n• **DDoS**: Thousands of compromised devices (botnet) — much harder to mitigate.",
            "**DDoS Risk:** 🟠 High. Can take your entire service offline. **Mitigation:** Rate limiting, CDN services (Cloudflare), blacklist offending IPs, auto-scaling.",
        ])

    def _r_what_is_malware(self, lang):
        if lang == 'ar':
            return random.choice([
                "**البرمجيات الخبيثة (Malware):**\nأي برنامج متصمم عشان يضر جهاز أو شبكة. بيشمل الفيروسات، حصان طروادة (Trojan)، وبرامج الفدية (Ransomware) اللي بتشفر ملفاتك.",
                "**Malware Types:**\n• **Virus**: ينسخ نفسه ويلحق ملفات.\n• **Trojan**: يتخفي كبرنامج مفيد.\n• **Ransomware**: يشفر ملفاتك ويطلب فدية 💰.",
                "**Malware Protection:**\n• خلي antivirus محدث.\n• افتحش المرفقات من ناس مش معروفة.\n• اعمل backup دوري.\n• استخدم firewall.",
            ])
        return random.choice([
            "**Malware:**\nMalicious software designed to harm or exploit any programmable device or network, including viruses, trojans, and ransomware.",
            "**Malware Types:**\n• **Virus**: Self-replicating, infects files.\n• **Trojan**: Disguised as legitimate software.\n• **Ransomware**: Encrypts files, demands payment 💰.",
            "**Malware Prevention:**\n• Keep antivirus updated.\n• Don't open suspicious attachments.\n• Regular backups.\n• Use a firewall and network monitoring.",
        ])

    def _r_what_is_phishing(self, lang):
        if lang == 'ar':
            return random.choice([
                "**التصيد الاحتيالي (Phishing):**\nهجوم بيعتمد على خداعك (غالباً بإيميل أو رسالة مزيفة) عشان تدي المهاجم معلومات حساسة زي كلمات السر أو بيانات البنك.",
                "**Phishing:**\nالمهاجم بيبعت إيميل يظهر إنه من بنك أو شركة معروفة، وبيقولك اضغط على لينك عشان تحدّث بياناتك. اللينك بيودي لموقع مزيف يسرق بياناتك.",
                "**Phishing Detection:** 🟡 Medium\n• دور على أخطاء إملائية.\n• اتأكد من الرابط قبل ما تضغط.\n• لو الإيميل يطلب بيانات شخصية، إرميه.\n• البنوك مبتطلبش بيانات بالإيميل.",
            ])
        return random.choice([
            "**Phishing:**\nA cybercrime where targets are contacted by someone posing as a legitimate institution to lure them into providing sensitive data.",
            "**How Phishing Works:**\nAttackers send emails that look like they're from banks or services. Links lead to fake login pages that steal your credentials.",
            "**Phishing Detection:** 🟡 Medium\n• Check for spelling errors and odd domains.\n• Hover links before clicking.\n• Legitimate companies never ask for passwords via email.",
        ])

    def _r_what_is_firewall(self, lang):
        if lang == 'ar':
            return random.choice([
                "**جدار الحماية (Firewall):**\nهو نظام أمني بيراقب ويتحكم في حركة المرور اللي داخلة وطالعة من الشبكة بناءً على قواعد محددة، عشان يمنع الهجمات. و Virex بيشتغل كجدار حماية ذكي!",
                "**Firewall أنواع:**\n• **Network Firewall**: بيحمي الشبكة كلها.\n• **WAF (Web App Firewall)**: زيّ Virex، بيحمي تطبيقات الويب من الهجمات زي SQLi و XSS.",
                "**Firewall Best Practices:**\n• اقفل كل الـ ports غير الضرورية.\n• استخدم allowlist بدل denylist.\n• حدّث القواعد بشكل دوري.\n• راقب الـ logs عشان تكتشف الاختراقات.",
            ])
        return random.choice([
            "**Firewall:**\nA network security system that monitors and controls traffic based on security rules. Virex acts as a smart WAF!",
            "**Firewall Types:**\n• **Network Firewall**: Protects entire network.\n• **WAF (Web App Firewall)**: Like Virex, protects web apps from SQLi, XSS, etc.",
            "**Firewall Best Practices:**\n• Close unnecessary ports.\n• Default-deny policy.\n• Regularly update rules.\n• Monitor logs for suspicious activity.",
        ])

    def _r_virex_info(self, lang):
        if lang == 'ar':
            return random.choice([
                "**عن Virex 🛡️:**\nنظام لحماية التطبيقات (WAF) معتمد على الذكاء الاصطناعي لاكتشاف وصد الهجمات في الوقت الفعلي. تم تطويره كمشروع تخرج علشان يكون درع قوي ضد التهديدات السيبرانية!",
                "**Virex Features:**\n• WAF بيحمي بالـ ML + Regex\n• SIEM Dashboard لتحليل الحوادث\n• كشف 6 أنواع هجمات\n• RBAC للتحكم في الصلاحيات\n• Attack Simulator للاختبار",
                "**Virex Architecture:**\n• Frontend: Dashboard (Flask + Bootstrap)\n• Backend: Flask API (port 5000)\n• ML: Random Forest + TF-IDF\n• DB: SQLite\n• AI Assistant: Dobby 🛡️",
            ])
        return random.choice([
            "**About Virex 🛡️:**\nAn AI-powered Web Application Firewall (WAF) designed to detect and block threats in real-time. Created as a graduation project to be a robust cyber shield!",
            "**Virex Core Features:**\n• ML + Regex WAF Engine\n• SIEM Dashboard for live monitoring\n• 6 attack type detection\n• RBAC with 4 roles\n• Attack Simulator for testing",
            "**Virex Tech Stack:**\n• Dashboard: Flask + Bootstrap (port 8070)\n• API: Flask + Gunicorn (port 5000)\n• ML Model: Random Forest + TF-IDF\n• Database: SQLite\n• Security Assistant: Dobby 🛡️",
        ])

    def _r_dashboard_help(self, lang):
        if lang == 'ar':
            return random.choice([
                "عشان تستخدم الداشبورد:\n1️⃣ **Incidents**: شوف الهجمات والحوادث المتسجلة.\n2️⃣ **Threats**: خريطة حية وتحليل للتهديدات.\n3️⃣ **Network**: راقب حركة المرور.\n4️⃣ **Settings**: لتعديل الحماية والـ Rate Limiting.",
                "شرح الصفحات:\n• **Dashboard**: نظرة عامة على إحصائيات الأمان.\n• **Threats**: تحليل التهديدات بالتفصيل.\n• **Blocked IPs**: قائمة IPs المحجوبة.\n• **ML Detections**: شوف الـ AI ايه اللي كشفه.",
                "عايز مساعدة في حاجة معينة؟ قولي:\n- \"عايز احصائيات\" عشان تقرير كامل\n- \"اشرح SQL Injection\" عشان تعرف عن الهجمة\n- \"في هجمات\" عشان آخر التهديدات\n- عندك log؟ ابعته لي وهحلله.",
            ])
        return random.choice([
            "To use the dashboard:\n1️⃣ **Incidents**: View recorded attacks.\n2️⃣ **Threats**: Live map & threat analysis.\n3️⃣ **Network**: Monitor incoming traffic.\n4️⃣ **Settings**: Configure firewall and rate limits.",
            "Dashboard pages:\n• **Dashboard**: Security stats overview.\n• **Threats**: Detailed threat analysis.\n• **Blocked IPs**: List of blocked addresses.\n• **ML Detections**: See what the AI caught.",
            "Need help with something specific? Try:\n- 'show stats' for a full system report\n- 'explain SQL Injection' to learn about an attack\n- 'recent threats' for latest attacks\n- Paste a log and I'll analyze it!",
        ])

    def _r_unknown(self, query, lang, prev_intent=None, prev_response=None):
        # Try to analyze as a payload first
        analysis = analyze_payload(query)
        if analysis:
            return generate_analysis_response(analysis, query, lang)

        # If there's a previous intent, offer relevant suggestions
        prev_hint = ""
        if prev_intent and prev_intent != "unknown":
            prev_hint_ar = f"\n\nكنت بتسأل عن **{prev_intent}** — عايز تكمل ولا تغير الموضوع؟"
            prev_hint_en = f"\n\nYou were asking about **{prev_intent}** — want to continue or switch topics?"
            prev_hint = prev_hint_ar if lang == 'ar' else prev_hint_en

        if lang == 'ar':
            return random.choice([
                f"مش فاهم قصدك كويس. 🤔\nممكن تسألني عن معنى الهجمات (زي DDoS, SQL, XSS)، أو تسأل عن إحصائيات النظام والتوصيات الأمنية.\n\nأو لو عندك log أو payload عايز تحلله، ابعته لي وهحللهولك.{prev_hint}",
                f"تقدر توضح أكتر؟ الكلمات دي جديدة عليا. 🛡️\nاسألني عن الهجمات أو لوحة التحكم وهجاوبك.\n\nأو ابعتي payload وهحللهولك.{prev_hint}",
                f"معلش مفهمتش. جرب تسألني سؤال مباشر عن حالة السيرفر أو أنواع التهديدات.\n\nأو ابعتي أي log أو request وهحللهولك.{prev_hint}",
            ])
        return random.choice([
            f"I'm not sure what you mean. 🤔\nYou can ask me to explain attacks (like DDoS, SQLi, XSS), or ask for system stats and security tips.\n\nOr paste a log/payload and I'll analyze it for you.{prev_hint}",
            f"Could you clarify? I handle security definitions, dashboard stats, and incident analysis. 🛡️\n\nYou can also paste a raw payload or log entry and I'll analyze it.{prev_hint}",
            f"Not quite sure. Try asking about attacks, incidents, or how to use the dashboard.\n\nOr send me a payload/log and I'll tell you what it is.{prev_hint}",
        ])

    def _match_solution_keyword(self, query: str) -> str | None:
        q = _normalize(query)
        # Check for SQLi
        if any(w in q for w in ["sql", "sqli", "injection", "حقن"]):
            return "sql_injection"
        # Check for XSS
        if any(w in q for w in ["xss", "cross site", "scripting", "سكريبت", "نصوص برمجه"]):
            return "xss"
        # Check for SSRF
        if any(w in q for w in ["ssrf", "server side", "تزوير طلبات"]):
            return "ssrf"
        # Check for CSRF
        if any(w in q for w in ["csrf", "cross site request", "تزوير الطلب"]):
            return "csrf"
        # Check for Command Injection
        if any(w in q for w in ["command", "shell", "subshell", "اوامر"]):
            return "command_injection"
        # Check for Path Traversal
        if any(w in q for w in ["path", "traversal", "directory", "مسار", "ملفات الخادم"]):
            return "path_traversal"
        # Check for Brute Force/Rate Limit
        if any(w in q for w in ["brute", "rate", "limit", "تخمين", "ضغط"]):
            return "brute_force"
        return None

    def _r_solution(self, sol_key: str, lang: str) -> str:
        sol = SOLUTIONS[sol_key]
        if lang == 'ar':
            title = sol["title_ar"]
            desc = sol["desc_ar"]
            steps = "\n".join(sol["steps_ar"])
            virex = sol["virex_ar"]
            return f"### {title}\n\n**الوصف:**\n{desc}\n\n**خطوات العلاج والوقاية:**\n{steps}\n\n**كيف يحميك Virex WAF؟**\n{virex}"
        else:
            title = sol["title_en"]
            desc = sol["desc_en"]
            steps = "\n".join(sol["steps_en"])
            virex = sol["virex_en"]
            return f"### {title}\n\n**Description:**\n{desc}\n\n**Remediation Steps:**\n{steps}\n\n**How does Virex WAF protect?**\n{virex}"

    def _ask_gemini(self, query: str, incident_id: str = None, history: list = None, lang: str = "en") -> str | None:
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            return None
        try:
            import google.generativeai as genai
            genai.configure(api_key=api_key)
            
            s = self.dashboard.stats
            stats_str = f"""
Current Live System Statistics:
- Total Requests: {s.get('total_requests', 0)}
- Blocked Requests: {s.get('blocked_requests', 0)}
- ML Detections: {s.get('ml_detections', 0)}
- SQL Injection Attempts: {s.get('sql_injection_attempts', 0)}
- XSS Attempts: {s.get('xss_attempts', 0)}
- Brute Force Attempts: {s.get('brute_force_attempts', 0)}
- Scanner Probes: {s.get('scanner_attempts', 0)}
- Rate Limit Hits: {s.get('rate_limit_hits', 0)}
"""
            incident_str = ""
            if incident_id:
                inc = self.dashboard.incidents.get(incident_id)
                if inc:
                    payload_d = inc.events[0].get('snippet', 'N/A') if inc.events else 'N/A'
                    incident_str = f"""
Currently Selected Incident context:
- Incident ID: {incident_id}
- Incident Code: {getattr(inc, 'incident_code', 'N/A')}
- Threat Category: {inc.category}
- Attacking Source IP: {inc.source_ip}
- Severity Level: {inc.severity}
- Status: {inc.status}
- Attack Sample Payload: {payload_d}
- Number of attack attempts: {len(inc.events)}
"""

            system_instruction = f"""
You are Dobby, the highly intelligent AI Security Assistant built into the Virex Web Application Firewall (WAF) and SIEM Dashboard.
Virex is a hybrid security system running a Flask API WAF (Port 5000) and a React SIEM Dashboard (Port 8070).

Virex WAF has a 7-Layer inspection model:
1. Skip health check/static files.
2. In-memory IP block cache check.
3. Centralized rate limiting (Redis sliding-window, fallback to DB).
4. Path scanner filter.
5. Rule-based inspection (Layer 1 regex patterns loaded from SQL).
6. Machine Learning inspection (Layer 2 Random Forest anomaly classifier. Block threshold >= 85%, monitor threshold >= 60%. Pre-filtered using a fast-path regex check).
7. Heuristic SSRF and CSRF rules.

Here are the live system metrics:
{stats_str}
{incident_str}

Please follow these instructions:
1. Answer queries directly, helpfully, and with deep security expertise.
2. If the user asks about an attack pattern or security problem, explain it clearly and provide practical solutions (such as secure coding tips in Python/JS, prepared statements, encoding, CSP headers, rate-limiting configs, input validation) related to their codebase or general security.
3. If an incident context is present, offer actionable advice for mitigating this specific incident (e.g. blocking the attacker IP, reviewing the specific logs, checking for leaks).
4. Support both Arabic (العربية) and English. Respond in the language used by the user.
5. Output clean, well-formatted Markdown with emojis.
"""
            model = genai.GenerativeModel(
                model_name="gemini-1.5-flash",
                system_instruction=system_instruction
            )
            
            prompt_content = []
            if history:
                history_text = "Prior Chat History:\n"
                for h in history[-5:]:
                    role_name = "User" if h.get("role") == "user" else "Assistant"
                    history_text += f"{role_name}: {h.get('content')}\n"
                prompt_content.append(history_text)
                
            prompt_content.append(f"User Query: {query}")
            
            response = model.generate_content("\n".join(prompt_content))
            return response.text.strip()
        except Exception as e:
            logger.error(f"[GEMINI] Generation failed: {e}")
            return None

    _user_context: dict = {}  # username → {last_intent, last_query, last_response}

    # ── Main Entry ────────────────────────────────────────────────

    def generate_response(
        self,
        user_query:  str,
        incident_id: str  = None,
        page_context       = None,
        history:     list = None,
        role:        str  = "user",
        username:    str  = "anonymous",
    ) -> str:

        time.sleep(0.2)
        lang     = self._lang(user_query)
        is_admin = (role == self.Role.ADMIN)
        intent   = _classify(user_query)

        # ── Follow-up detection ──────────────────────────────────
        prev = self._user_context.get(username, {})
        if intent == "follow_up" and prev.get("last_intent") and prev["last_intent"] not in ("follow_up", "unknown", "greeting"):
            intent = prev["last_intent"]
            # Reuse the previous query context for enriched responses
            user_query = prev.get("last_query", user_query)

        # ── Store context BEFORE generating response ─────────────
        self._user_context[username] = {
            "last_intent": intent,
            "last_query": user_query,
        }

        # ── Check Gemini first for complex/informational queries ──
        api_key = os.getenv("GEMINI_API_KEY")
        local_fast_intents = {"greeting", "thanks", "goodbye", "identity", "how_are_you"}
        
        if api_key and HAS_GEMINI and intent not in local_fast_intents:
            resp = self._ask_gemini(user_query, incident_id, history, lang)
            if resp:
                self._user_context[username]["last_response"] = resp
                return resp

        # ── Check local security solution dictionary fallback ──
        sol_key = self._match_solution_keyword(user_query)
        if sol_key:
            resp = self._r_solution(sol_key, lang)
            self._user_context[username]["last_response"] = resp
            return resp

        # ── Auto-detect: if query looks like a payload/log, analyze it ──
        analysis = analyze_payload(user_query)
        if analysis and analysis["is_malicious"]:
            similarity_with_intents = max(
                _intent_score(_normalize(user_query), INTENTS[i]["triggers"])
                for i in INTENTS
            )
            if similarity_with_intents < 0.5:
                resp = generate_analysis_response(analysis, user_query, lang)
                self._user_context[username]["last_response"] = resp
                return resp

        # ── Route intent → handler ───────────────────────────────
        def respond(handler, *args, **kwargs):
            resp = handler(*args, **kwargs)
            self._user_context[username]["last_response"] = resp
            return resp

        # non-admin: block sensitive queries
        if not is_admin and intent in ("top_attacker",) and not incident_id:
            return respond(lambda: "عذراً، التفاصيل دي للمسؤولين فقط. 🔒" if lang == 'ar' else "Sorry, this information is restricted to admins. 🔒")

        # intent dispatch table
        handler_map = {
            "identity":       lambda: self._r_identity(lang),
            "greeting":       lambda: self._r_greeting(lang),
            "how_are_you":    lambda: self._r_how_are_you(lang),
            "thanks":         lambda: self._r_thanks(lang),
            "goodbye":        lambda: self._r_goodbye(lang),
            "system_status":  lambda: self._r_status(lang),
            "top_attacker":   lambda: self._r_top_attacker(lang, is_admin),
            "top_attack":     lambda: self._r_top_attack(lang),
            "recent_threats": lambda: self._r_recent_threats(lang, is_admin),
            "security_tips":  lambda: self._r_security_tips(lang),
            "what_is_sqli":   lambda: self._r_what_is_sqli(lang),
            "what_is_xss":    lambda: self._r_what_is_xss(lang),
            "what_is_ddos":   lambda: self._r_what_is_ddos(lang),
            "what_is_malware": lambda: self._r_what_is_malware(lang),
            "what_is_phishing": lambda: self._r_what_is_phishing(lang),
            "what_is_firewall": lambda: self._r_what_is_firewall(lang),
            "virex_info":     lambda: self._r_virex_info(lang),
            "dashboard_help": lambda: self._r_dashboard_help(lang),
        }
        if intent in handler_map:
            return respond(handler_map[intent])

        # attack type stats
        if intent in ("sql_stats", "xss_stats", "brute_stats",
                      "scanner_stats", "ratelimit_stats", "ml_stats"):
            return respond(self._r_attack_stat, intent, lang)

        # incident_action / incident_why without incident
        if intent == "incident_action" and not incident_id:
            return respond(self._r_security_tips, lang)
        if intent == "incident_why" and not incident_id:
            return respond(lambda: "لو بتسأل عن سبب هجمة معينة، ياريت تحددها أو تفتحها من صفحة الـ Incidents عشان أقدر أحللها لك صح. 🔍" if lang == 'ar' else "If you're asking why a specific attack happened, please provide context or open it from the Incidents page so I can analyze it for you. 🔍")

        # analyze payload intent
        if intent == "analyze_payload":
            analysis = analyze_payload(user_query)
            if analysis:
                return respond(lambda: generate_analysis_response(analysis, user_query, lang))
            return respond(lambda: "أرسلي الـ payload أو الـ log اللي عايز تحلله وهحللهولك. 🔍" if lang == 'ar' else "Send me the payload or log you want analyzed and I'll analyze it for you. 🔍")

        # incident-specific
        if incident_id:
            inc = self.dashboard.incidents.get(incident_id)
            if not inc:
                return respond(lambda: "الحادثة دي مش موجودة في السجلات." if lang == 'ar' else "This incident was not found in records.")
            if intent == "incident_why":
                return respond(self._r_incident_why, inc, lang, is_admin)
            if intent == "incident_action":
                return respond(self._r_incident_action, inc, lang, is_admin)
            return respond(self._r_incident_why, inc, lang, is_admin)

        # unknown
        return respond(lambda: self._r_unknown(user_query, lang, prev.get("last_intent"), prev.get("last_response")))