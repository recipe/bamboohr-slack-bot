BambooHR "Who Is Out" Slack Bot
==

BambooHR Slack Bot integrates with your BambooHR account
and reports who is out today.

Features
--

* Automatically syncs Slack user profile statuses for all members
  of your team based on the BambooHR time-off table. A status lasts until the end of
  the last day of the time off. Consecutive time-offs and BambooHR company holidays
  right after the time off are treated as one period.
  It is re-checked on every poll, so it follows changes of the time off and of the
  user's time zone, and it is cleared when the time off is withdrawn.
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

The service runs as the unprivileged `bamboohr-slack-bot` user, which reads the config through its group.
Copy the sample config file keeping it readable only by root and the service:
```bash
install -m 0640 -g bamboohr-slack-bot /etc/bamboohr-slack-bot/config.yml-sample /etc/bamboohr-slack-bot/config.yml
```

Provide `slack_client_id`, `slack_client_secret`, and `slack_signing_secret`,
which are available in your Slack application settings.

By default, the service listens on the loopback only (`server_endpoint: "127.0.0.1:8087"`) and
a reverse proxy terminates TLS in front of it, so it can share a server with other sites.
For nginx, the package provides an example server in `/usr/share/doc/bamboohr-slack-bot/nginx.conf`:
```bash
cp /usr/share/doc/bamboohr-slack-bot/nginx.conf /etc/nginx/sites-available/bamboohr-slack-bot
# set server_name and the certificate paths, e.g. issued by Let's Encrypt
ln -s /etc/nginx/sites-available/bamboohr-slack-bot /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx
```

To serve HTTPS without a reverse proxy, set `ssl_cert` and `ssl_key`, and a `server_endpoint`
reachable from Slack. The `bamboohr-slack-bot` user must be able to read the certificate files,
and a port below 1024 requires the `CAP_NET_BIND_SERVICE` capability
(see the comment in the `bamboohr-slack-bot.service` unit). A plain HTTP endpoint other than
the loopback is logged as a warning.

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
