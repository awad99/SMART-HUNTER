from flask import Flask, request

app = Flask(__name__)

# Dummy database
users = {"admin": {"password": "password123", "email": "admin@example.com"}}

@app.route("/")
def index():
    return "CSRF Test Labs"

# Lab 1: GET based CSRF (State changing operation via GET)
@app.route("/lab1/change_email", methods=["GET"])
def lab1_change_email():
    # In a real app, we'd check session, but here we just simulate it by taking a user param or assuming logged in
    new_email = request.args.get("email")
    if new_email:
        # Vulnerable: State change happens via GET request without any CSRF protection
        users["admin"]["email"] = new_email
        return f"Email changed successfully to {new_email} for admin!"
    return "Please provide an email via the ?email= parameter"

# Lab 2: POST based CSRF without any token
@app.route("/lab2/change_email", methods=["POST", "GET"])
def lab2_change_email():
    if request.method == "GET":
        return '''
            <form action="/lab2/change_email" method="POST">
                <input type="text" name="email" placeholder="New Email">
                <input type="submit" value="Change Email">
            </form>
        '''
    if request.method == "POST":
        new_email = request.form.get("email")
        if new_email:
            # Vulnerable: No CSRF token is checked
            users["admin"]["email"] = new_email
            return f"Email changed successfully to {new_email} for admin!"
    return "Error"

if __name__ == "__main__":
    app.run(debug=True, port=5000)
