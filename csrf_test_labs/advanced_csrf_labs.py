import json
from flask import Flask, request, jsonify, make_response

app = Flask(__name__)

# Dummy data for validation
valid_tokens = {"user1_token", "user2_token", "attacker_token"}

@app.route("/")
def index():
    html = "<h1>Advanced CSRF Test Labs</h1><ul>"
    for i in range(1, 16):
        html += f'''
        <li>
            <h2>Lab {i}</h2>
            <form action="/api/{i}/update" method="POST">
                <input type="text" name="csrf_token" value="test_token">
                <input type="submit" value="Submit">
            </form>
        </li>
        '''
    html += "</ul>"
    return html

# 1. No protection at all (POST)
@app.route("/api/1/update", methods=["POST"])
def api_1():
    return "Success 1"

# 2. Token expected but omitted bypass
@app.route("/api/2/update", methods=["POST"])
def api_2():
    token = request.form.get("csrf_token")
    if token is not None and token != "correct_token":
        return "Invalid Token", 403
    return "Success 2"

# 3. Method bypass (Checks POST, ignores GET)
@app.route("/api/3/update", methods=["GET", "POST"])
def api_3():
    if request.method == "POST":
        token = request.form.get("csrf_token")
        if token != "correct_token":
            return "Invalid Token", 403
    return "Success 3"

# 4. Method override bypass (_method parameter)
@app.route("/api/4/update", methods=["POST"])
def api_4():
    method = request.form.get("_method", "POST")
    token = request.form.get("csrf_token")
    if method == "POST" and token != "correct_token":
        return "Invalid Token", 403
    return "Success 4"

# 5. Method override bypass (X-HTTP-Method-Override header)
@app.route("/api/5/update", methods=["POST"])
def api_5():
    override = request.headers.get("X-HTTP-Method-Override")
    token = request.form.get("csrf_token")
    if override != "PUT" and token != "correct_token":
         return "Invalid Token", 403
    return "Success 5"

# 6. Weak Token (Predictable)
@app.route("/api/6/update", methods=["POST"])
def api_6():
    # E.g. token is just base64 of the username
    token = request.form.get("csrf_token")
    if token != "dXNlcjE=": # user1 in base64
        return "Invalid Token", 403
    return "Success 6"

# 7. Token not tied to user session
@app.route("/api/7/update", methods=["POST"])
def api_7():
    token = request.form.get("csrf_token")
    if token not in valid_tokens:
        return "Invalid Token", 403
    return "Success 7"

# 8. Double Submit Cookie (No session tie)
@app.route("/api/8/update", methods=["POST"])
def api_8():
    cookie_token = request.cookies.get("csrf_token")
    form_token = request.form.get("csrf_token")
    if not cookie_token or cookie_token != form_token:
        return "Invalid Token", 403
    return "Success 8"

# 9. Referer header check - omitted bypass
@app.route("/api/9/update", methods=["POST"])
def api_9():
    referer = request.headers.get("Referer")
    if referer and "localhost" not in referer:
        return "Invalid Referer", 403
    return "Success 9"

# 10. Referer header check - contains bypass
@app.route("/api/10/update", methods=["POST"])
def api_10():
    referer = request.headers.get("Referer", "")
    if "localhost" not in referer:
        return "Invalid Referer", 403
    return "Success 10"

# 11. Referer header check - startswith bypass
@app.route("/api/11/update", methods=["POST"])
def api_11():
    referer = request.headers.get("Referer", "")
    # Vulnerable to http://localhost.attacker.com
    if not referer.startswith("http://localhost"):
        return "Invalid Referer", 403
    return "Success 11"

# 12. Origin header check - null bypass
@app.route("/api/12/update", methods=["POST"])
def api_12():
    origin = request.headers.get("Origin", "")
    if origin != "http://localhost" and origin != "null":
        return "Invalid Origin", 403
    return "Success 12"

# 13. JSON CSRF (Accepts text/plain and parses as JSON)
@app.route("/api/13/update", methods=["POST"])
def api_13():
    # Browser allows sending text/plain cross-origin without preflight
    if request.content_type != "application/json" and request.content_type != "text/plain":
        return "Invalid Content-Type", 403
    try:
        data = json.loads(request.data)
        return "Success 13"
    except:
        return "Invalid JSON", 400

# 14. CORS Arbitrary Origin
@app.route("/api/14/update", methods=["POST", "OPTIONS"])
def api_14():
    origin = request.headers.get("Origin", "*")
    resp = make_response("Success 14")
    resp.headers["Access-Control-Allow-Origin"] = origin
    resp.headers["Access-Control-Allow-Credentials"] = "true"
    return resp

# 15. CORS Regex Bypass
@app.route("/api/15/update", methods=["POST", "OPTIONS"])
def api_15():
    origin = request.headers.get("Origin", "")
    resp = make_response("Success 15")
    # Vulnerable to http://attackerlocalhost:5000
    if origin.endswith("localhost:5000"):
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Access-Control-Allow-Credentials"] = "true"
    return resp

if __name__ == "__main__":
    app.run(debug=True, port=5000)
