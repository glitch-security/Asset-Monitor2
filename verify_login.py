"""
Verify AssetMonitor login flow using Playwright
"""
from playwright.sync_api import sync_playwright, TimeoutError
import sys
import time

def verify_login(url, username, password):
    """Verify login flow and UI elements"""
    results = {
        "passed": [],
        "failed": [],
        "warnings": []
    }

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False)
        context = browser.new_context()
        page = context.new_page()

        try:
            # 1. Navigate to root URL
            print("\n[1] Navigating to", url)
            page.goto(url, timeout=10000)
            results["passed"].append("Root URL loads without crashing")

            # Check if redirected to login
            current_url = page.url
            if "/login" in current_url or current_url.endswith("/login"):
                results["passed"].append("Root redirects to /login page")
            else:
                results["failed"].append(f"Expected /login redirect, got {current_url}")

            # 2. Check login page elements
            print("\n[2] Checking login page elements")
            time.sleep(1)

            # Check for username field
            try:
                username_input = page.wait_for_selector('input[name="username"], input[id="username"], input[placeholder*="username" i]', timeout=5000)
                results["passed"].append("Username input field found")
            except TimeoutError:
                results["failed"].append("Username input field not found")

            # Check for password field
            try:
                password_input = page.wait_for_selector('input[name="password"], input[id="password"], input[type="password"]', timeout=5000)
                results["passed"].append("Password input field found")
            except TimeoutError:
                results["failed"].append("Password input field not found")

            # Check for login button
            try:
                login_btn = page.wait_for_selector('button[type="submit"], button:has-text("Login"), button:has-text("Sign In")', timeout=5000)
                results["passed"].append("Login button found")
            except TimeoutError:
                results["warnings"].append("Could not find login button with standard selectors")

            # 3. Attempt login with credentials
            print(f"\n[3] Attempting login with {username}/{password}")

            page.fill('input[name="username"], input[id="username"]', username)
            page.fill('input[name="password"], input[type="password"]', password)

            # Click login button
            page.click('button[type="submit"]')

            # 4. Check for successful login
            print("\n[4] Checking for successful login")
            time.sleep(2)

            current_url = page.url
            if "/login" not in current_url:
                results["passed"].append(f"Login successful - redirected to {current_url}")
            else:
                # Check for error message
                try:
                    error = page.wait_for_selector('.error, .alert, [class*="error"]', timeout=2000)
                    error_text = error.text_content()
                    results["failed"].append(f"Login failed - error message: {error_text}")
                except TimeoutError:
                    results["failed"].append("Login failed - no error message displayed")

            # 5. Verify dashboard loads
            if "/login" not in current_url:
                print("\n[5] Verifying dashboard elements")

                # Check for main navigation
                try:
                    nav = page.wait_for_selector('nav, [role="navigation"], .navbar', timeout=5000)
                    results["passed"].append("Main navigation found")
                except TimeoutError:
                    results["warnings"].append("Could not find main navigation element")

                # Check for common dashboard elements
                try:
                    page.wait_for_selector('text=/dashboard|targets|settings/i', timeout=5000)
                    results["passed"].append("Dashboard content detected")
                except TimeoutError:
                    results["warnings"].append("Dashboard content not immediately visible")

            # 6. Take screenshot for visual verification
            print("\n[6] Taking screenshot")
            page.screenshot(path="login_verification_screenshot.png")
            results["passed"].append("Screenshot saved to login_verification_screenshot.png")

            # 7. Check for JavaScript errors
            print("\n[7] Checking for JavaScript errors")
            # Note: Playwright doesn't directly expose console errors without setup
            # This is a placeholder for that capability
            results["warnings"].append("JavaScript console errors not checked in this script")

            # Keep browser open for manual inspection
            print("\n[INFO] Browser will remain open for 5 seconds for manual inspection...")
            time.sleep(5)

        except Exception as e:
            results["failed"].append(f"Exception during test: {str(e)}")
            print(f"\n[ERROR] Exception: {e}")

        finally:
            browser.close()

    return results

if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:5000"
    username = sys.argv[2] if len(sys.argv) > 2 else "admin"
    password = sys.argv[3] if len(sys.argv) > 3 else "admin123"

    print("=" * 60)
    print("AssetMonitor Login Flow Verification")
    print("=" * 60)

    results = verify_login(url, username, password)

    print("\n" + "=" * 60)
    print("RESULTS SUMMARY")
    print("=" * 60)

    print(f"\n✓ Passed ({len(results['passed'])}):")
    for item in results['passed']:
        print(f"  ✓ {item}")

    if results['failed']:
        print(f"\n✗ Failed ({len(results['failed'])}):")
        for item in results['failed']:
            print(f"  ✗ {item}")

    if results['warnings']:
        print(f"\n⚠ Warnings ({len(results['warnings'])}):")
        for item in results['warnings']:
            print(f"  ⚠ {item}")

    # Exit with appropriate code
    sys.exit(0 if not results['failed'] else 1)
