from playwright.sync_api import sync_playwright


def capture_website_screenshot(url: str):

    try:
        with sync_playwright() as p:

            browser = p.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-dev-shm-usage"]
            )

            context = browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                           "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                viewport={"width": 1366, "height": 768}
            )

            page = context.new_page()

            if not url.startswith("http"):
                url = "https://" + url

            page.goto(
                url,
                timeout=30000,
                wait_until="domcontentloaded"
            )

            page.wait_for_timeout(3000)  # allow JS to render

            screenshot = page.screenshot(full_page=True)

            browser.close()

            return screenshot

    except Exception as e:
        print("Screenshot error:", e)
        return None
