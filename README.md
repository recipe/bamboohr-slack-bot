BambooHR "who is out" Slack bot
==

BambooHR Slack bot is integrated with your BambooHR account
and can tell who is out today.

Features
--

* Automatically synchronizes current Slack user profile statuses
  for all members of your team based on BambooHR time-off table.
* Gives an information about who is out today by using the `/whoisout` slash command.

Installation
--

* Create a new Slack application
* Create a new slash command `/whoisout` and set the request URL as `https://your.host/command`
* Make sure that the "Escape channels, users, and links sent to your app" is enabled.
* Add a new OAuth Redirect URL as `https://your.host/redirect`
* Required permissions scopes: `users.profile:write`,
  `users.profile:read`,
  `users:read.email`,
  `users:read`,
  `commands`.
* Download and install binary package for your operating system and architecture. Let's say it's linux amd64 (Ubuntu 22.04):

```bash
curl -L -O https://github.com/recipe/bamboohr-slack-bot/releases/download/0.0.3/bamboohr-slack-bot_0.0.3_linux_amd64.tar.gz
tar -xvzf bamboohr-slack-bot_0.0.3_linux_amd64.tar.gz
cd bamboohr-slack-bot_0.0.3
dpkg -i bamboohr-slack-bot_0.0.3-1.deb
```

Configuration
--
Set the config for the application:
```bash
cp /etc/bamboohr-slack-bot/config.yml-sample /etc/bamboohr-slack-bot/config.yml
```

Change the `server_endpoint`. Provide `slack_client_id`, `slack_client_secret` and `slack_signing_secret` that
should be obtained while installing the Slack application.
Use offered randomly generated `cryptokey` or provide your own with the same length (64 characters).
If you want the application to work over the HTTPS, you should generate the SSL certificate.
You may generate either a self-signed certificate or install [Let's encrypt](https://letsencrypt.org/) certificate.

To start the service run the following command:
```bash
systemctl start bamboohr-slack-bot
```

Initialization
--
If the application is installed and running you can use the slash command
`/whoisout help` to see all available options.

`/whoisout install <bamboohr_subdomain> <bamboohr_secret>`command is necessary to bind your
BambooHR account to a Slack workspace. The profile statuses of users that exist in the Slack workspace
will be updated automatically according to BambooHR time-off table.
The application matches users by comparing their email addresses.

