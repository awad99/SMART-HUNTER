import json
import os
import random

dataset_file = r"C:\Users\awad\Downloads\SMART-HUNTER-main\SMART-HUNTER-main\Data\Datasets\Datasets_for_Model_NLP\nlp_finetuning_dataset.jsonl"

system_prompt = "You are an expert cybersecurity AI. Analyze HTTP traffic and identify vulnerabilities like IDOR, XXE, and CSRF. Explain your reasoning."

csrf_examples = [
    {
        "req": "POST /api/settings/email HTTP/1.1\nHost: target.com\nContent-Type: application/x-www-form-urlencoded\nCookie: session=xyz123\n\nnew_email=attacker@evil.com",
        "res": "HTTP/1.1 200 OK\n\nEmail updated successfully.",
        "vuln": "Cross-Site Request Forgery (CSRF) - Missing Token",
        "reason": "The request changes user state (email) but does not include an anti-CSRF token in the body or headers. The session cookie is sent automatically, allowing an attacker to forge this request."
    },
    {
        "req": "POST /user/delete HTTP/1.1\nHost: app.site.com\nContent-Type: application/x-www-form-urlencoded\nCookie: auth=session\n\nid=1024",
        "res": "HTTP/1.1 200 OK\n\nUser deleted.",
        "vuln": "Cross-Site Request Forgery (CSRF) - Token Validation Bypass",
        "reason": "The state-changing request does not contain a CSRF token. The server accepted the request without validating a token, indicating the protection is missing or can be bypassed."
    },
    {
        "req": "GET /api/transfer?amount=1000&to_account=9999 HTTP/1.1\nHost: bank.local\nCookie: sessionid=abcdef\n\n",
        "res": "HTTP/1.1 200 OK\n\nTransfer complete.",
        "vuln": "Cross-Site Request Forgery (CSRF)",
        "reason": "The application uses a GET request for a state-changing operation (fund transfer). GET requests are highly susceptible to CSRF as they can be easily triggered via image tags or simple links without any tokens."
    },
    {
        "req": "POST /profile/update HTTP/1.1\nHost: target.com\nContent-Type: application/json\nCookie: session=xyz\n\n{\"password\": \"newpass123\"}",
        "res": "HTTP/1.1 200 OK\n\n{\"status\": \"Password changed\"}",
        "vuln": "Cross-Site Request Forgery (CSRF) - Missing Token",
        "reason": "The request modifies sensitive account data using a JSON payload. There is no CSRF token included in the headers or the body, leaving the endpoint vulnerable if CORS allows it or via flash/form-based workarounds."
    },
    {
        "req": "POST /api/settings HTTP/1.1\nHost: api.target.com\nContent-Type: application/x-www-form-urlencoded\nCookie: session=12345\nReferer: https://attacker.com/csrf.html\n\nusername=hacked",
        "res": "HTTP/1.1 200 OK\n\nSettings updated.",
        "vuln": "Cross-Site Request Forgery (CSRF) - Referer Not Validated",
        "reason": "The server processed the request even though the Referer header pointed to a third-party, untrusted domain ('attacker.com'). This indicates missing or weak Referer/Origin validation alongside a missing CSRF token."
    },
    {
        "req": "GET /api/user_data HTTP/1.1\nHost: target.com\nCookie: session=123\nOrigin: https://evil.com",
        "res": "HTTP/1.1 200 OK\nAccess-Control-Allow-Origin: https://evil.com\nAccess-Control-Allow-Credentials: true\n\n{\"user_id\": 1, \"email\": \"admin@target.com\"}",
        "vuln": "CSRF (CORS Misconfiguration)",
        "reason": "The server reflects the 'Origin' header from the request ('https://evil.com') in the 'Access-Control-Allow-Origin' response header and sets 'Access-Control-Allow-Credentials: true'. This allows an attacker to read sensitive data cross-origin."
    }
]

generated_data = []

# Generate 30 variations to properly augment the dataset
for _ in range(30):
    ex = random.choice(csrf_examples)
    entry = {
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"Analyze this HTTP request/response pair for vulnerabilities:\n\nREQUEST:\n{ex['req']}\n\nRESPONSE:\n{ex['res']}"},
            {"role": "assistant", "content": f"Vulnerability: {ex['vuln']}\nReasoning: {ex['reason']}"}
        ]
    }
    generated_data.append(entry)

with open(dataset_file, 'a', encoding='utf-8') as f:
    for item in generated_data:
        f.write(json.dumps(item) + '\n')

print(f"Appended {len(generated_data)} CSRF examples to {dataset_file}")
