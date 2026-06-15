# Advanced CSRF Vulnerability Techniques

This document details 15 distinct categories of CSRF vulnerabilities often found in real-world bug bounty scenarios. These represent the fundamental logic flaws that scanners must detect. Creating 50 or more labs usually results in minor syntax permutations of these core 15 logic flaws, so having a robust set covering all major vectors is the most effective way to test a tool.

## 1. No Protection
The most basic flaw where an endpoint performing a state-changing operation (POST, PUT, DELETE) does not implement any CSRF tokens or Origin/Referer checks.

## 2. Token Expected but Omitted Bypass
The backend checks if the token is valid *only if it is present*. An attacker can simply remove the `csrf_token` parameter from the request, and the server processes it successfully.

## 3. Method Bypass (GET/POST)
The backend enforces CSRF token checks on POST requests, but the same endpoint allows state-changing operations via GET requests without checking the token.

## 4. Method Override Bypass (`_method`)
Frameworks sometimes allow overriding the HTTP method using a parameter like `_method=PUT`. If the CSRF middleware only protects POST requests, an attacker can send a POST request with `_method=PUT` to bypass the check.

## 5. Method Override Bypass (Header)
Similar to #4, but using the `X-HTTP-Method-Override` header. Some firewalls or middleware might not apply CSRF checks if they see this header.

## 6. Weak/Predictable Token
The token is generated using a predictable algorithm, such as simply base64 encoding the username or a predictable timestamp, allowing an attacker to guess or calculate the token.

## 7. Token Not Tied to Session
The application maintains a pool of valid CSRF tokens but does not map them to specific user sessions. An attacker can obtain a valid token from their own account and use it to forge a request against the victim.

## 8. Double Submit Cookie (No Session Tie)
The application expects the token in a cookie and a request parameter to match. If the application has a subdomain vulnerability or is otherwise susceptible to "cookie tossing", an attacker can set the cookie to a known value and send the matching parameter.

## 9. Referer Omitted Bypass
The application checks the `Referer` header but fails open if the header is completely absent. Attackers can use `<meta name="referrer" content="no-referrer">` to strip the referer header during the attack.

## 10. Referer Contains Bypass
The application poorly validates the `Referer` header by just checking if the target domain is *anywhere* in the string. Attackers can bypass this by putting the target domain in the path or query string: `http://attacker.com/?target=localhost`.

## 11. Referer Startswith Bypass
The application checks if the `Referer` starts with the target domain (`http://localhost`). Attackers can register a subdomain like `http://localhost.attacker.com` to bypass the check.

## 12. Origin Null Bypass
The application poorly validates the `Origin` header and explicitly allows the `null` origin. Attackers can trigger requests from a sandboxed iframe or a data URI, which sends an `Origin: null` header.

## 13. JSON CSRF via `text/plain`
The application accepts JSON data but doesn't strictly enforce `Content-Type: application/json`. Browsers allow cross-origin requests without a preflight (OPTIONS) request if the content type is `text/plain`. An attacker can send JSON payloads disguised as `text/plain`.

## 14. CORS Arbitrary Origin
The application dynamically reflects whatever origin is sent in the `Origin` header into `Access-Control-Allow-Origin` and sets `Access-Control-Allow-Credentials: true`. This effectively disables CORS and allows CSRF via XMLHttpRequests.

## 15. CORS Regex Bypass
The application uses a flawed regex or string matching to validate the origin for CORS. For example, checking if the origin *ends with* `localhost:5000` allows `http://attackerlocalhost:5000`.

## Testing your tool
Run `python advanced_csrf_labs.py` to start the server. Point SMART-HUNTER at `http://localhost:5000/api/1/update` through `/api/15/update` to test its CSRF detection capabilities across these various edge cases.
