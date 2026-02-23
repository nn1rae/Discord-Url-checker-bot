import bot_engine.engine as engine



if __name__ == "__main__":
    print("Starting Discord Link Safety Bot...")
    try:
        engine.bot.run(engine.DISCORD_TOKEN)
    except engine.discord.errors.PrivilegedIntentsRequired:
        print("ERROR: Missing required privileged intents in Discord Developer Portal.")
        print(
            "Enable MESSAGE CONTENT INTENT for your bot at https://discord.com/developers/applications"
        )
