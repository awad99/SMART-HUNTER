# CSRF Vulnerability Logic and Problems

This document describes the logic behind the Cross-Site Request Forgery (CSRF) vulnerabilities present in the `csrf_labs.py` application. These labs are generic and designed specifically for testing vulnerability scanners locally.

## What is CSRF?
Cross-Site Request Forgery (CSRF) is an attack that forces an authenticated user to execute unwanted actions on a web application in which they are currently authenticated.

## Lab 1: GET-Based CSRF
**Endpoint:** `/lab1/change_email`

**Problem Logic:**
*   **State Change via GET:** The application performs a state-changing operation (updating an email address) using an HTTP GET request, which violates HTTP standards (GET should be idempotent).
*   **No Unpredictable Token:** There is no unpredictable token (like an anti-CSRF token) required in the request.
*   **Scanner Target:** A vulnerability scanner should detect that a GET request accepts parameters that modify state without verifying an anti-CSRF token.

## Lab 2: POST-Based CSRF (Missing Token)
**Endpoint:** `/lab2/change_email`

**Problem Logic:**
*   **Missing Anti-CSRF Token:** While it uses a POST request (which is appropriate for state changes), it completely lacks any Anti-CSRF token verification logic. It blindly accepts any POST request.
*   **Scanner Target:** A vulnerability scanner should detect that the form submitted via POST does not contain any hidden token field (`csrf_token`, `_csrf`, etc.), and that the endpoint accepts the request without validating such a token.

## How to use for testing your tool
1. Install Flask if you don't have it: `pip install Flask`
2. Run the application: `python csrf_labs.py` (It will run on `http://localhost:5000`)
3. Point your testing tool to the following endpoints to verify if it can detect these missing protections:
   - `http://localhost:5000/lab1/change_email`
   - `http://localhost:5000/lab2/change_email`
