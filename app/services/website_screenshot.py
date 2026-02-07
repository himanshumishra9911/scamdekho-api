from playwright.sync_api import sync_playwright


def capture_website_screenshot(url: str):

    try:
        with sync_playwright() as p:

            browser = p.chromium.launch(headless=True)

            page = browser.new_page()

            page.goto(url, timeout=15000)

            screenshot = page.screenshot(full_page=True)

            browser.close()

            return screenshot

    except Exception as e:
        print("Screenshot error:", e)
        return None
