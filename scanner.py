
import requests
from datetime import datetime


SCAN_LOG_FILE = "scan_logs.txt"


def scan_website(url):

    results = {}

    try:

        # AUTO HTTPS FIX
        if not url.startswith("http://") and not url.startswith("https://"):

            url = "https://" + url

        # WEBSITE REQUEST
        response = requests.get(
            url,
            timeout=5
        )

        results["status_code"] = response.status_code

        # SERVER DETECTION
        server = response.headers.get(
            "Server",
            "Unknown"
        )

        results["server"] = server

        # SECURITY HEADERS
        security_headers = [

            "Content-Security-Policy",
            "X-Frame-Options",
            "Strict-Transport-Security",
            "X-Content-Type-Options",
            "Referrer-Policy"

        ]

        headers_found = []

        headers_missing = []

        for header in security_headers:

            if header in response.headers:

                headers_found.append(header)

            else:

                headers_missing.append(header)

        results["headers_found"] = headers_found

        results["headers_missing"] = headers_missing

        # ADMIN PANEL CHECK
        admin_paths = [

            "/admin",
            "/administrator",
            "/admin/login",
            "/login",
            "/user/login",
            "/wp-admin",
            "/dashboard",
            "/cpanel",
            "/adminpanel",
            "/backend",
            "/signin",
            "/auth/login"

        ]

        admin_pages = []

        for path in admin_paths:

            try:

                admin_url = url + path

                admin_response = requests.get(
                    admin_url,
                    timeout=3
                )

                if admin_response.status_code in [200, 301, 302]:

                    admin_pages.append(admin_url)

            except:

                pass

        results["admin_pages"] = admin_pages

        # SECURITY SCORE
        security_score = 100

        security_score -= len(headers_missing) * 10

        security_score -= len(admin_pages) * 5

        if security_score < 0:

            security_score = 0

        results["security_score"] = security_score

        # THREAT LEVEL
        threat_level = "LOW"

        if len(headers_missing) >= 2:

            threat_level = "MEDIUM"

        if len(admin_pages) >= 2:

            threat_level = "HIGH"

        if security_score <= 50:

            threat_level = "CRITICAL"

        results["threat_level"] = threat_level

        # STORE SCAN LOGS
        log_entry = f"""
Time: {datetime.now()}
Scan Target: {url}
Status Code: {response.status_code}
Server: {server}
Threat Level: {threat_level}
Security Score: {security_score}
Headers Found: {', '.join(headers_found) if headers_found else 'None'}
Missing Headers: {', '.join(headers_missing) if headers_missing else 'None'}
Admin Pages Found: {len(admin_pages)}
Admin URLs: {', '.join(admin_pages) if admin_pages else 'None'}
Attack Type: Website Security Scan
-------------------------
"""

        with open(SCAN_LOG_FILE, "a") as file:

            file.write(log_entry)

    except Exception as e:

        results["error"] = str(e)

    return results

