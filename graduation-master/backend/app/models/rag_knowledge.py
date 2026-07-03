"""
RAG Knowledge Base Model

Contains the structured data/knowledge that the Security RAG System is trained on.
"""

# Security Guardrail Keywords
SECURITY_KEYWORDS = [
    'security', 'attack', 'vulnerability', 'hack', 'exploit', 'injection', 
    'xss', 'csrf', 'buffer', 'overflow', 'malware', 'phishing', 'dos', 'ddos', 
    'payload', 'breach', 'auth', 'cyber', 'virus', 'traversal', 'deserialization',
    'sqli', 'sql', 'hi', 'hello', 'hey', 'greetings', 'clear', 'reset', 'waf', 'siem'
]

# Core Knowledge Base
KNOWLEDGE_BASE = [
    {
        "title": "SQL Injection (SQLi)",
        "content": "SQL Injection is an attack where malicious SQL statements are inserted into entry fields for execution. It allows attackers to spoof identity, tamper with existing data, cause repudiation issues, and access sensitive data.",
        "type": "Attack"
    },
    {
        "title": "Cross-Site Scripting (XSS)",
        "content": "XSS attacks are a type of injection, in which malicious scripts are injected into otherwise benign and trusted websites. It occurs when an attacker uses a web application to send malicious code, generally in the form of a browser side script, to a different end user.",
        "type": "Attack"
    },
    {
        "title": "Cross-Site Request Forgery (CSRF)",
        "content": "CSRF is an attack that forces an end user to execute unwanted actions on a web application in which they're currently authenticated. It targets state-changing requests, not theft of data.",
        "type": "Attack"
    },
    {
        "title": "Buffer Overflow",
        "content": "A buffer overflow occurs when a program or process attempts to write more data to a fixed length block of memory (a buffer) than the buffer is allocated to hold. This can lead to system crashes or arbitrary code execution.",
        "type": "Bug/Vulnerability"
    },
    {
        "title": "Broken Access Control",
        "content": "Restrictions on what authenticated users are allowed to do are often not properly enforced. Attackers can exploit these flaws to access unauthorized functionality and/or data.",
        "type": "Bug/Vulnerability"
    },
    {
        "title": "Insecure Deserialization",
        "content": "Insecure deserialization often leads to remote code execution. Even if it does not result in remote code execution, it can be used to perform attacks, including replay attacks, injection attacks, and privilege escalation.",
        "type": "Bug/Vulnerability"
    },
    {
        "title": "Denial of Service (DoS)",
        "content": "A Denial-of-Service (DoS) attack is meant to shut down a machine or network, making it inaccessible to its intended users. DoS attacks accomplish this by flooding the target with traffic, or sending it information that triggers a crash.",
        "type": "Attack"
    },
    {
        "title": "Path Traversal (Directory Traversal)",
        "content": "A path traversal attack aims to access files and directories that are stored outside the web root folder. By manipulating variables that reference files with dot-dot-slash (../) sequences and its variations.",
        "type": "Attack/Bug"
    }
]
