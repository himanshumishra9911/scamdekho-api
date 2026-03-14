from playwright.async_api import async_playwright
import asyncio

async def capture_website_screenshot(url: str):
    try:
        if not url.startswith("http"):
            url = "https://" + url

        print(f"[SCREENSHOT] Starting for: {url}")

        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                    "--disable-software-rasterizer",
                    "--disable-extensions",
                    "--single-process",
                    "--memory-pressure-off",
                    "--disable-features=VizDisplayCompositor",
                ]
            )
            print(f"[SCREENSHOT] Browser launched")

            context = await browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                           "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                viewport={"width": 1280, "height": 900},
                java_script_enabled=True,
            )

            page = await context.new_page()

            try:
                await page.goto(
                    url,
                    timeout=20000,
                    wait_until="domcontentloaded"
                )
                print(f"[SCREENSHOT] Page loaded successfully")
            except Exception as e:
                print(f"[SCREENSHOT] Page load error (continuing anyway): {e}")

            # 2 sec wait — page settle hone do
            await asyncio.sleep(2)

            screenshot = await page.screenshot(
                full_page=False,
                type="jpeg",
                quality=80
            )

            await browser.close()

            if screenshot and len(screenshot) > 10000:
                print(f"[SCREENSHOT] Success — size: {len(screenshot)} bytes")
                return screenshot
            else:
                print(f"[SCREENSHOT] Too small — likely blank page: {len(screenshot) if screenshot else 0} bytes")
                return None

    except Exception as e:
        print(f"[SCREENSHOT] FATAL ERROR: {e}")
        return None
