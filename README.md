BambooHR "Who Is Out" Slack Bot
==

BambooHR Slack Bot integrates with your BambooHR account
and reports who is out today.

Features
--

* Automatically syncs Slack user profile statuses for all members
  of your team based on the BambooHR time-off table.
* Shows who is out today via the `/whoisout` slash command.

Installation
--

* Create a new Slack application.
* Create a new slash command `/whoisout` and set the request URL to `https://your.host/command`.
* Make sure that "Escape channels, users, and links sent to your app" is enabled.
* Add a new OAuth Redirect URL: `https://your.host/redirect`.
* Required permission scopes: `users.profile:write`,
  `users.profile:read`,
  `users:read.email`,
  `users:read`,
  `commands`.
* Download and install the binary package for your operating system and architecture. For example, for Linux amd64 (Ubuntu 24.04):

```bash
curl -L -O https://github.com/recipe/bamboohr-slack-bot/releases/download/1.0.0/bamboohr-slack-bot_1.0.0_linux_amd64.tar.gz
tar -xvzf bamboohr-slack-bot_1.0.0_linux_amd64.tar.gz
cd bamboohr-slack-bot_1.0.0
dpkg -i bamboohr-slack-bot_1.0.0-1.deb
```

Configuration
--

Copy the sample config file:
```bash
cp /etc/bamboohr-slack-bot/config.yml-sample /etc/bamboohr-slack-bot/config.yml
```

Set `server_endpoint` and provide `slack_client_id`, `slack_client_secret`, and `slack_signing_secret`,
which are available in your Slack application settings.
Use the pre-generated `cryptokey` value or provide your own of the same length (64 characters).
To run the application over HTTPS, you will need an SSL certificate —
either self-signed or issued by [Let's Encrypt](https://letsencrypt.org/).

To start the service, run:
```bash
systemctl start bamboohr-slack-bot
```

Initialization
--

Once the application is installed and running, use the slash command
`/whoisout help` to see all available options.

The `/whoisout install <bamboohr_subdomain> <bamboohr_secret>` command binds your
BambooHR account to a Slack workspace. Profile statuses for users present in both
Slack and BambooHR will be updated automatically based on the BambooHR time-off table.
Users are matched by their email address.
