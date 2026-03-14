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
                    "--disable-background-networking",
                    "--disable-default-apps",
                    "--disable-sync",
                    "--disable-translate",
                    "--hide-scrollbars",
                    "--metrics-recording-only",
                    "--mute-audio",
                    "--no-first-run",
                    "--safebrowsing-disable-auto-update",
                    "--single-process",
                    "--memory-pressure-off",
                    "--disable-features=VizDisplayCompositor",
                ]
            )
            print(f"[SCREENSHOT] Browser launched")

            context = await browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                           "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                viewport={"width": 1280, "height": 720},
                java_script_enabled=True,
            )

            await context.route("**/*", lambda route: (
                route.abort()
                if route.request.resource_type in ["image", "media", "font", "stylesheet"]
                else route.continue_()
            ))

            page = await context.new_page()

            try:
                await page.goto(
                    url,
                    timeout=15000,
                    wait_until="domcontentloaded"
                )
                print(f"[SCREENSHOT] Page loaded successfully")
            except Exception as e:
                print(f"[SCREENSHOT] Page load error (continuing anyway): {e}")

            await asyncio.sleep(1)

            screenshot = await page.screenshot(
                full_page=False,
                type="jpeg",
                quality=70
            )

            await browser.close()

            if screenshot:
                print(f"[SCREENSHOT] Success — size: {len(screenshot)} bytes")
            else:
                print(f"[SCREENSHOT] Failed — empty screenshot")

            return screenshot

    except Exception as e:
        print(f"[SCREENSHOT] FATAL ERROR: {e}")
        return None
