import discord
from discord.ext import commands
import os
from dotenv import load_dotenv
from tools.url_checker import URLChecker
from tools.patterns.url_patterns import URL_PATTERN


# Load API keys from .env file
load_dotenv()

# Configuration
DISCORD_TOKEN = os.getenv("DISCORD_BOT_TOKEN")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")


# Bot setup
intents = discord.Intents.default()
intents.message_content = True
intents.guilds = True
intents.guild_messages = True
intents.dm_messages = True

bot = commands.Bot(command_prefix="!", intents=intents)


# setup URL checker
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
        verification_failures = []
        missing_api_key_warning_sent = False

        for url in urls:
            print(f"Checking URL: {url}")
            result = await url_checker.check_url(url)

            if not result["checked"]:
                # Could not check URL (API key missing or error)
                if "VirusTotal API key not configured" in result["details"].get(
                    "error", ""
                ):
                    if not missing_api_key_warning_sent:
                        await message.channel.send(
                            f"Warning: Link detection is active but VirusTotal API is not configured. "
                            f"Cannot verify safety of links."
                        )
                        missing_api_key_warning_sent = True
                else:
                    error_message = result["details"].get("error", "Unknown error")
                    print(f"Could not verify URL {url}: {error_message}")
                    verification_failures.append(url)
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

        if verification_failures:
            await message.channel.send(
                f"⚠️ Could not verify {len(verification_failures)} link(s) right now due to scan delay or API limits. "
                f"Please retry in a moment."
            )

    # Process commands
    await bot.process_commands(message)


@bot.event
async def on_command_error(ctx, error):
    if isinstance(error, commands.CommandNotFound):
        return
    print(f"Command error for '{ctx.message.content}': {error}")
