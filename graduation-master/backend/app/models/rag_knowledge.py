"""
RAG Knowledge Base Model

Contains the structured data/knowledge that the Security RAG System is trained on.
Expanded with comprehensive Arabic & English security guides.
"""

# Security Guardrail Keywords (Bilingual: English & Arabic)
SECURITY_KEYWORDS = [
    'security', 'attack', 'vulnerability', 'hack', 'exploit', 'injection', 
    'xss', 'csrf', 'buffer', 'overflow', 'malware', 'phishing', 'dos', 'ddos', 
    'payload', 'breach', 'auth', 'cyber', 'virus', 'traversal', 'deserialization',
    'sqli', 'sql', 'hi', 'hello', 'hey', 'greetings', 'clear', 'reset', 'waf', 'siem',
    'brute', 'force', 'scanner', 'scanning', 'nmap', 'nikto', 'sqlmap', 'wpscan',
    'rate', 'limit', 'limiting', 'ssrf', 'path', 'directory', 'command', 'exec', 'execute',
    'session', 'broken', 'jwt', 'cookie', 'same site', 'token',
    'ثغرة', 'ثغرات', 'هجوم', 'هجمات', 'حقن', 'اختراق', 'تحديد', 'معدل', 'طلبات', 'قوة', 
    'غاشمة', 'تخمين', 'سيرفر', 'مجلد', 'مسار', 'مصادقة', 'حماية', 'تزوير', 'أمن', 'أمني', 'أمنية'
]

# Core Knowledge Base (Arabic and English)
KNOWLEDGE_BASE = [
    # --- 1. General Vulnerabilities ---
    {
        "title": "Vulnerabilities & Lifecycle (English)",
        "content": "A vulnerability is a weakness in system, app, or network exploited to gain unauthorized access, leak data, or execute code. Lifecycle: Discovery, Disclosure (Responsible/Full), Classification (CVE, CWE, CVSS score 0-10, OWASP Top 10), Exploitation (PoC), Patching, Zero-Day. Essential WAF concepts: False Positive, False Negative, Signature-based, Anomaly-based (ML), Defense in depth, Least Privilege.",
        "type": "General Security"
    },
    {
        "title": "الثغرات الأمنية ودورة حياتها (Arabic)",
        "content": "الثغرة الأمنية هي ضعف في نظام أو تطبيق يمكن المهاجم من الوصول غير المصرح به أو تسريب بيانات. دورة حياتها: الاكتشاف، الإفصاح، التصنيف (CVE, CWE, CVSS من 0 إلى 10، OWASP Top 10)، الاستغلال (PoC)، الإصلاح (Patching)، وثغرات اليوم الصفر (Zero-Day). مفاهيم WAF أساسية: False Positive، False Negative، كشف بالبصمة (Signature)، كشف بالانحراف (ML)، الدفاع المعمق، وأقل الصلاحيات.",
        "type": "General Security"
    },
    
    # --- 2. SQL Injection ---
    {
        "title": "SQL Injection (SQLi) (English)",
        "content": "SQL Injection (CWE-89, CVSS 7.0-9.8) occurs when user input is concatenated directly into SQL queries without sanitization. Types: In-band (Error-based, Union-based), Blind (Boolean-based, Time-based e.g., SLEEP), Out-of-band. Evasion: comments injection, case variation, encoding. Mitigations: Prepared statements (parameterized queries), ORM usage, Least Privilege DB users, Input Validation, WAF layers.",
        "type": "Attack"
    },
    {
        "title": "حقن استعلامات قاعدة البيانات (SQL Injection) (Arabic)",
        "content": "ثغرة SQL Injection (CWE-89) تحدث عند دمج مدخلات المستخدم مباشرة في استعلام SQL دون تنقية. أنواعها: In-band (Error-based, Union-based)، و Blind (Boolean-based, Time-based باستخدام SLEEP)، و Out-of-band. أساليب التخطي: Comments injection، تغيير حالة الحروف، الـ Encoding. الحماية: Parameterized Queries (الأساسي)، استخدام ORM، تطبيق Least Privilege، فحص المدخلات، جدار حماية التطبيقات (WAF).",
        "type": "Attack"
    },

    # --- 3. Cross-Site Scripting (XSS) ---
    {
        "title": "Cross-Site Scripting (XSS) (English)",
        "content": "XSS (CWE-79, CVSS 5.0-8.8) allows injecting malicious scripts (JS/HTML) into web pages viewed by others. Types: Stored/Persistent (saved in DB), Reflected (reflected in response, requires user action), DOM-based (client-side DOM manipulation). Payloads: <script>, img/svg onload/onerror, iframe. Mitigations: Output encoding/escaping, Content Security Policy (CSP), HttpOnly flags on cookies, React/Vue auto-escaping, DOMPurify sanitization.",
        "type": "Attack"
    },
    {
        "title": "حقن الكود العابر للمواقع (XSS) (Arabic)",
        "content": "ثغرة XSS (CWE-79) تسمح بحقن كود JavaScript/HTML ضار داخل صفحات الويب لتنفيذه في متصفح الضحية. أنواعها: مخزن Stored XSS (الأخطر، يحفظ بقاعدة البيانات)، منعكس Reflected XSS (يرجع فوراً بالرد)، وعبر المتصفح DOM-based XSS. الحماية: Output Encoding/Escaping، تطبيق سياسة أمان المحتوى (CSP)، استخدام HttpOnly للـ cookies، مكتبات التنقية مثل DOMPurify.",
        "type": "Attack"
    },

    # --- 4. Brute Force ---
    {
        "title": "Brute Force & Credential Stuffing (English)",
        "content": "Brute Force (CWE-307) involves guessing credentials automatically. Types: Simple brute force, Dictionary attack (wordlists like rockyou.txt), Credential stuffing (using leaked credentials), Password spraying (one password tested against many accounts), Reverse brute force. Mitigations: Account lockout policy, Rate limiting, CAPTCHAs, Multi-Factor Authentication (MFA), strong password complexity policy, Exponential backoff.",
        "type": "Attack"
    },
    {
        "title": "هجمات القوة الغاشمة وتخمين الحسابات (Brute Force) (Arabic)",
        "content": "هجوم Brute Force (CWE-307) هو محاولة تخمين كلمة المرور آلياً. أنواعه: تخمين بسيط، هجوم القاموس (Dictionary Attack)، Credential Stuffing (استخدام تسريبات سابقة)، Password Spraying (تجربة كلمة مرور واحدة على حسابات متعددة). الحماية: سياسة قفل الحساب (Lockout)، تحديد معدل الطلبات (Rate Limiting)، اختبار CAPTCHA، المصادقة الثنائية (MFA)، وسياسة كلمات مرور قوية.",
        "type": "Attack"
    },

    # --- 5. Scanners ---
    {
        "title": "Security Scanners & Reconnaissance (English)",
        "content": "Scanners automate finding open ports, services, and vulnerabilities. Types: Network (Nmap for OS/Service fingerprinting), Web (Nikto, ZAP, Burp Suite, Acunetix), Directory (Gobuster, ffuf), CMS (WPScan), Vulnerability scanners (Nessus, OpenVAS). Signatures target Nikto, sqlmap, gobuster strings and path scans like .env, .git/config, wp-login.php. Mitigations: Rate limiting, IP reputation block, Honeypots, WAF signatures, Fail2Ban.",
        "type": "Reconnaissance"
    },
    {
        "title": "أدوات الفحص والاستطلاع (Scanners) (Arabic)",
        "content": "الـ Scanners أدوات آلية لاكتشاف المنافذ والثغرات والخدمات. أنواعها: فحص شبكة (Nmap)، فحص تطبيقات (Nikto, Burp Suite, OWASP ZAP)، فحص مسارات (Gobuster, ffuf)، وفحص شامل (Nessus, OpenVAS). تكشف في الـ logs بطلبات مكثفة لمسارات حساسة مثل .env و .git/config و wp-login.php و User-Agents معروفة. الحماية: Rate Limiting، حظر الـ IPs، استخدام Honeypots، وأنظمة Fail2Ban.",
        "type": "Reconnaissance"
    },

    # --- 6. Rate Limiting ---
    {
        "title": "Rate Limiting Algorithms & Protection (English)",
        "content": "Rate Limiting prevents resource abuse, brute force, and DDoS. Algorithms: Fixed Window, Sliding Window Log, Sliding Window Counter, Token Bucket (most popular, allows bursts), Leaky Bucket (processes requests at a constant rate). Levels: Per IP, Per User, Per Endpoint (sensitive routes like /login), Global. Standard response is HTTP 429 Too Many Requests with Retry-After header. Used in SIEM as anomaly indicators.",
        "type": "Mitigation/Architecture"
    },
    {
        "title": "تحديد معدل الطلبات (Rate Limiting) (Arabic)",
        "content": "آلية حماية لتحديد عدد الطلبات التي يمكن للمستخدم إرسالها خلال فترة معينة لمنع Brute Force و DDoS. خوارزمياته: Fixed Window، Sliding Window، Token Bucket (الأكثر شيوعاً، يسمح بـ burst)، و Leaky Bucket. يطبق على مستوى الـ IP، المستخدم، أو مسار معين (مثل /login). يرد خادم الويب بـ HTTP 429 (Too Many Requests) مع Retry-After header.",
        "type": "Mitigation/Architecture"
    },

    # --- 7. Cross-Site Request Forgery (CSRF) ---
    {
        "title": "Cross-Site Request Forgery (CSRF) (English)",
        "content": "CSRF (CWE-352, CVSS 4.0-8.0) tricks an authenticated victim browser into sending unauthorized requests to a site because cookies are attached automatically. Payload: hidden HTML form auto-submitting POST/GET requests. Mitigations: CSRF Tokens (unique token verified per request), SameSite Cookie Attribute (Strict/Lax to block cross-site cookie transit), Origin/Referer headers validation, Re-authentication for sensitive actions.",
        "type": "Attack"
    },
    {
        "title": "تزوير الطلبات عبر المواقع (CSRF) (Arabic)",
        "content": "ثغرة CSRF (CWE-352) تجبر متصفح المستخدم المصادق على تنفيذ إجراءات غير مقصودة في موقع يثق به، مستغلاً إرسال المتصفح لملفات تعريف الارتباط (cookies) تلقائياً. الحماية: استخدام رموز CSRF Tokens الفريدة مع كل فورم، تعيين خاصية SameSite للـ Cookies إلى Strict أو Lax، التحقق من Origin و Referer headers، وطلب كلمة المرور للعمليات الحساسة.",
        "type": "Attack"
    },

    # --- 8. Server-Side Request Forgery (SSRF) ---
    {
        "title": "Server-Side Request Forgery (SSRF) (English)",
        "content": "SSRF (CWE-918, CVSS up to 9.0+) tricks the server into making HTTP requests to internal networks or private IP ranges (e.g. 127.0.0.1, localhost, 169.254.169.254 cloud metadata endpoint). Used to scan internal ports or steal IAM credentials. Mitigations: strict whitelisting of allowed destination domains, blocking Private IP ranges (10.0.0.0/8, 192.168.0.0/16), disabling non-HTTP schemes, IMDSv2 Cloud Metadata protection.",
        "type": "Attack"
    },
    {
        "title": "تزوير الطلبات من جهة السيرفر (SSRF) (Arabic)",
        "content": "ثغرة SSRF (CWE-918) تمكن المهاجم من إجبار السيرفر على إرسال طلبات HTTP لجهات يحددها، بما فيها شبكات داخلية وموارد خاصة (مثل localhost وعنوان metadata للـ Cloud: 169.254.169.254) لاستخراج بيانات حساسة كأوراق اعتماد IAM. الحماية: عمل Whitelist للدومينات المسموحة، حظر النطاقات الخاصة (Private IPs)، وتعطيل البروتوكولات مثل file:// و ftp://.",
        "type": "Attack"
    },

    # --- 9. Path Traversal ---
    {
        "title": "Path Traversal (Directory Traversal) (English)",
        "content": "Path Traversal (CWE-22, CVSS 5.0-9.8) lets attackers read files outside the web root (e.g. /etc/passwd or win.ini) using '../' sequences. Evasions: double URL encoding, Unicode encoding, null byte injection. Mitigations: whitelisting file paths, using basename() helper to drop folder paths, checking canonical absolute paths, running app under chroot jail or Docker with Least Privilege.",
        "type": "Attack/Vulnerability"
    },
    {
        "title": "تخطي مسارات المجلدات (Path Traversal) (Arabic)",
        "content": "ثغرة Path Traversal (CWE-22) تسمح بالوصول لملفات خارج مجلد الويب الرئيسي (مثل /etc/passwd) باستخدام ../. أساليب التخطي تشمل الترميز المزدوج (Double Encoding) أو Unicode. الحماية: استخدام القوائم البيضاء للملفات المسموحة، استخدام دالة os.path.basename() لإزالة المجلدات، التحقق منCanonical Path (المسار الحقيقي المطلق)، وتشغيل التطبيق داخل بيئة معزولة (Docker).",
        "type": "Attack/Vulnerability"
    },

    # --- 10. Command Injection ---
    {
        "title": "OS Command Injection (English)",
        "content": "OS Command Injection (CWE-78, CVSS 8.0-10.0) executes arbitrary commands on the server OS when unsanitized user input is executed by system shells (e.g., executing '; whoami', '| cat /etc/passwd'). Leads directly to Remote Code Execution (RCE). Mitigations: avoid system shell calls entirely, use parameterized API arrays (e.g., subprocess arguments instead of single strings), strict whitelisting of input characters.",
        "type": "Attack"
    },
    {
        "title": "حقن أوامر نظام التشغيل (Command Injection) (Arabic)",
        "content": "ثغرة OS Command Injection (CWE-78) تسمح بتنفيذ أوامر نظام عشوائية على السيرفر عندما يتم تمرير مدخلات المستخدم مباشرة لأوامر Shell (مثل ; whoami أو | cat /etc/passwd). تؤدي مباشرة لاختراق السيرفر بالكامل (RCE). الحماية: تجنب استدعاء Shell commands نهائياً، استخدام Parameterized APIs (مثل تمرير المدخلات كـ Array)، وفحص المدخلات بدقة.",
        "type": "Attack"
    },

    # --- 11. Broken Authentication ---
    {
        "title": "Broken Authentication & Session Management (English)",
        "content": "Broken Auth (CWE-287 / CWE-384, CVSS 6.0-9.0) involves vulnerabilities in authentication logic. Examples: session IDs exposed in URLs, session fixation, storing passwords using weak hashing (like MD5), weak JWT validation (algorithm none). Mitigations: renew session IDs after login, use robust hashing (bcrypt, Argon2) with salt, enforce MFA, validate JWT signatures, set short session expiry times.",
        "type": "Bug/Vulnerability"
    },
    {
        "title": "ضعف المصادقة وإدارة الجلسات (Arabic)",
        "content": "ثغرات Broken Authentication (CWE-287) تحدث بسبب ضعف منطق التحقق من الجلسات. أمثلتها: ظهور Session ID في الروابط، عدم انتهاء صلاحية الجلسة عند تسجيل الخروج، وتشفير كلمات المرور بخوارزميات ضعيفة (مثل MD5). الحماية: تجديد Session ID بعد تسجيل الدخول، تشفير كلمات المرور باستخدام bcrypt أو Argon2، تفعيل MFA، والتحقق الصارم من توقيع الـ JWT.",
        "type": "Bug/Vulnerability"
    }
]
