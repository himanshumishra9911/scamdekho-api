from playwright.async_api import async_playwright
import asyncio

async def capture_website_screenshot(url: str):
    try:
        if not url.startswith("http"):
            url = "https://" + url

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
                    "--single-process",          # ← Memory saver
                    "--memory-pressure-off",
                    "--disable-features=VizDisplayCompositor",
                ]
            )

            context = await browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                           "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                viewport={"width": 1280, "height": 720},  # Smaller viewport
                java_script_enabled=True,                  # JS on — sites load properly
            )

            # Block heavy resources — images CSS fonts nahi load honge
            await context.route("**/*", lambda route: (
                route.abort()
                if route.request.resource_type in ["image", "media", "font", "stylesheet"]
                else route.continue_()
            ))

            page = await context.new_page()

            try:
                await page.goto(
                    url,
                    timeout=15000,                # 15 sec max
                    wait_until="domcontentloaded" # DOMContentLoaded pe hi screenshot
                )
            except Exception:
                # Timeout hone pe bhi screenshot try karo
                pass

            # Wait — 1 sec enough hai
            await asyncio.sleep(1)

            # Viewport only — full_page=False saves memory
            screenshot = await page.screenshot(
                full_page=False,
                type="jpeg",      # JPEG — PNG se 60% chhota
                quality=70        # Quality 70 — AI ke liye enough
            )

            await browser.close()
            return screenshot

    except Exception as e:
        print(f"Screenshot error: {e}")
        return None
