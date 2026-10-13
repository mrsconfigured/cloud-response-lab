print("DEBUG: test_discord.py started")
import os

import requests
from dotenv import load_dotenv


# Load settings from the local .env file.
load_dotenv()

webhook_url = os.getenv("DISCORD_WEBHOOK_URL")

if not webhook_url:
    raise RuntimeError(
        "DISCORD_WEBHOOK_URL is missing. Check your local .env file."
    )

# Send a harmless simulated security alert to Discord.
alert = {
    "content": (
        "**Cloud Response Lab — Test Alert**\n"
        "Event: Simulated AWS access-key creation\n"
        "Severity: Medium\n"
        "Status: Test only; no response action taken."
    )
}

response = requests.post(
    webhook_url,
    json=alert,
    timeout=15,
)

response.raise_for_status()

print("Test alert sent successfully to Discord.")