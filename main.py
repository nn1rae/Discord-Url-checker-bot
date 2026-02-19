import discord
from discord.ext import commands
import re
import aiohttp
import os
from typing import Optional, Dict
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Bot setup
intents = discord.Intents.default()
intents.message_content = True
intents.guilds = True
intents.guild_messages = True
intents.dm_messages = True

bot = commands.Bot(command_prefix="!", intents=intents)

# Configuration
DISCORD_TOKEN = os.getenv("DISCORD_BOT_TOKEN")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

# URL regex pattern to detect links
URL_PATTERN = re.compile(
    r"\b(?:https?://|ftp://)?"  # optional scheme
    r"(?:www\.)?"  # optional www
    r"(?:"  # domain or IP
    r"(?:[a-zA-Z0-9-]{1,63}\.)+"  # subdomains
    r"[a-zA-Z]{2,63}"  # TLD
    r"|"  # OR
    r"(?:\d{1,3}\.){3}\d{1,3}"  # IPv4
    r")"
    r"(?::\d{2,5})?"  # optional port
    r"(?:/[^\s]*)?"  # optional path
    r"\b",
    re.IGNORECASE,
)


class URLChecker:
    def __init__(self, api_key: Optional[str]):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"

    async def check_url(self, url: str) -> Dict:
        if not self.api_key:
            return {
                "safe": True,
                "details": {"error": "VirusTotal API key not configured"},
                "checked": False,
            }

        headers = {"x-apikey": self.api_key}

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.base_url}/urls", headers=headers, data={"url": url}
                ) as response:
                    if response.status != 200:
                        return {
                            "safe": True,
                            "details": {"error": f"API error: {response.status}"},
                            "checked": False,
                        }

                    submit_data = await response.json()
                    analysis_id = submit_data["data"]["id"]

                async with session.get(
                    f"{self.base_url}/analyses/{analysis_id}", headers=headers
                ) as response:
                    if response.status != 200:
                        return {
                            "safe": True,
                            "details": {"error": f"Analysis error: {response.status}"},
                            "checked": False,
                        }

                    result = await response.json()
                    stats = result["data"]["attributes"]["stats"]

                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)

                    is_safe = malicious == 0 and suspicious == 0

                    return {
                        "safe": is_safe,
                        "details": {
                            "malicious": malicious,
                            "suspicious": suspicious,
                            "harmless": stats.get("harmless", 0),
                            "undetected": stats.get("undetected", 0),
                        },
                        "checked": True,
                    }

        except Exception as e:
            print(f"Error checking URL: {e}")
            return {"safe": True, "details": {"error": str(e)}, "checked": False}


url_checker = URLChecker(VIRUSTOTAL_API_KEY)


@bot.event
async def on_ready():
    print(f"{bot.user} ONLINE - ID: {bot.user.id}")
    print(f"Connected to {len(bot.guilds)} guild(s)")


@bot.event
async def on_guild_join(guild):
    print(f"Joined new guild: {guild.name} ({guild.id})")


@bot.event
async def on_message(message):
    # ignore own msgs
    if message.author.bot:
        return

    # find urls in message
    urls = URL_PATTERN.findall(message.content)

    if urls:
        print(f"Found {len(urls)} URL(s) in message from {message.author}")

        for url in urls:
            print(f"Checking URL: {url}")
            result = await url_checker.check_url(url)

            if not result["checked"]:
                # Could not check URL (API key missing or error)
                if "VirusTotal API key not configured" in result["details"].get(
                    "error", ""
                ):
                    await message.channel.send(
                        f"Warning: Link detection is active but VirusTotal API is not configured. "
                        f"Cannot verify safety of links."
                    )
                continue

            if not result["safe"]:
                details = result["details"]
                malicious = details["malicious"]
                suspicious = details["suspicious"]

                embed = discord.Embed(
                    title="MALICIOUS ACTIVITY DETECTED",
                    description=f"A potentially malicious link was detected in this message.",
                    color=discord.Color.red(),
                )
                embed.add_field(
                    name="URL",
                    value=f"||{url}||",  # Spoiler tag to hide the URL
                    inline=False,
                )
                embed.add_field(
                    name="Threat Level",
                    value=f"🆘 Malicious: {malicious}\n⚠️ Suspicious: {suspicious}",
                    inline=False,
                )
                embed.add_field(
                    name="Action Taken",
                    value="Message has been deleted for safety.",
                    inline=False,
                )
                embed.set_footer(text=f"Sender: {message.author.name}")

                # Try to delete the message
                try:
                    await message.delete()
                    await message.channel.send(embed=embed)

                    # Try to DM the user
                    try:
                        dm_embed = discord.Embed(
                            title="Your message was removed",
                            description=f"Your message in {message.guild.name} (#{message.channel.name}) was removed because it contained a malicious link.",
                            color=discord.Color.orange(),
                        )
                        dm_embed.add_field(
                            name="Link", value=f"||{url}||", inline=False
                        )
                        dm_embed.add_field(
                            name="Why was it removed?",
                            value=f"{malicious} security vendor(s) flagged this as malicious and {suspicious} flagged it as suspicious.",
                            inline=False,
                        )
                        await message.author.send(embed=dm_embed)
                    except discord.Forbidden:
                        print(f"Could not DM {message.author}")

                except discord.Forbidden:
                    # Bot doesn't have permission to delete
                    await message.channel.send(
                        f"{message.author.mention} ⚠️ **WARNING**: Your message contains a dangerous link! "
                        f"({malicious} vendors flagged it as malicious)"
                    )
            else:
                # URL is safe
                print(f"✓ URL is safe: {url}")
                await message.add_reaction("✅")

    # Process commands
    await bot.process_commands(message)


@bot.event
async def on_command_error(ctx, error):
    if isinstance(error, commands.CommandNotFound):
        return
    print(f"Command error for '{ctx.message.content}': {error}")


if __name__ == "__main__":
    print("Starting Discord Link Safety Bot...")
    try:
        bot.run(DISCORD_TOKEN)
    except discord.errors.PrivilegedIntentsRequired:
        print("ERROR: Missing required privileged intents in Discord Developer Portal.")
        print(
            "Enable MESSAGE CONTENT INTENT for your bot at https://discord.com/developers/applications"
        )
