from playwright.async_api import async_playwright


async def capture_website_screenshot(url: str):

    try:
        if not url.startswith("http"):
            url = "https://" + url

        async with async_playwright() as p:

            browser = await p.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-dev-shm-usage"]
            )

            context = await browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                           "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                viewport={"width": 1366, "height": 768}
            )

            page = await context.new_page()

            await page.goto(
                url,
                timeout=30000,
                wait_until="domcontentloaded"
            )

            await page.wait_for_timeout(3000)

            screenshot = await page.screenshot(full_page=True)

            await browser.close()

            return screenshot

    except Exception as e:
        print("Screenshot error:", e)
        return None
