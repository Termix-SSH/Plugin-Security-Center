<div align="center">

<img src="https://termix.site/img/logo.svg" width="120" alt="Termix Logo" />

<h1>Security Center</h1>

<p>Audit SSH keys, rotate them and scan hosts for known vulnerabilities over SSH</p>

<!-- VIDEO:START -->
<!-- VIDEO:END -->

</div>

<br />

## Overview

Security Center looks at the SSH keys on your hosts, tells you which ones are weak, old or unprotected, and helps you replace them. It also checks the packages installed on each host against the OSV database and shows the known vulnerabilities, with the fixed version and a flag for the ones attackers already use.

Read the [docs](https://docs.termix.site/plugins/security-center) to set it up and use it.

<br />

## Features

- Inventory of authorized keys, host keys and private keys on every host
- Findings for weak or old keys, keys without a passphrase, loose file permissions and risky sshd settings
- Rotate the key Termix logs in with. The new key is checked before the old one is removed
- Remove a key from a host by fingerprint, and make new host keys
- Vulnerability scan with severity, fixed versions and the CISA known exploited flag, for Debian, Ubuntu, Alpine, Rocky Linux and AlmaLinux
- Alerts for new critical vulnerabilities and key problems
- A dashboard card, signals and events for Operations and Automations

<br />

## Sponsors

For a paid sponsor spot, email [mail@termix.site](mailto:mail@termix.site).

<!-- SPONSORS:START -->

<div align="center">

<br />

<a href="https://www.blacksmith.sh/">
  <img src="https://termix.site/img/sponsors/blacksmith.svg" height="40" alt="Blacksmith" />
</a>
&nbsp;&nbsp;&nbsp;
<a href="https://www.cloudflare.com/">
  <img src="https://termix.site/img/sponsors/cloudflare.png" height="40" alt="Cloudflare" />
</a>
&nbsp;&nbsp;&nbsp;
<a href="https://akamai.com/">
  <img src="https://termix.site/img/sponsors/akamai.svg" height="40" alt="Akamai" />
</a>
&nbsp;&nbsp;&nbsp;
<a href="https://aws.amazon.com/">
  <img src="https://termix.site/img/sponsors/aws.png" height="40" alt="AWS" />
</a>
&nbsp;&nbsp;&nbsp;
<a href="https://rackgenius.com/">
  <img src="https://termix.site/img/sponsors/rackgenius.png" height="40" alt="Rack Genius" />
</a>
&nbsp;&nbsp;&nbsp;
<a href="https://ginernet.com/">
  <img src="https://termix.site/img/sponsors/ginernet.png" height="40" alt="Ginernet" />
</a>
&nbsp;&nbsp;&nbsp;
<a href="https://www.hetzner.com/?mtm_campaign=termix&mtm_medium=referral&mtm_content=sponsoring_link">
  <img src="https://termix.site/img/sponsors/hetzner.png" height="40" alt="Hetzner" />
</a>
&nbsp;&nbsp;&nbsp;
<a href="https://emberswan.com/">
  <img src="https://termix.site/img/sponsors/emberswan.png" height="40" alt="Ember Swan" />
</a>

</div>

<!-- SPONSORS:END -->

<br />

## Support

Bugs and ideas for Security Center go in this repo: [report a bug](https://github.com/Termix-SSH/Plugin-Security-Center/issues/new?template=bug_report.yml) or [request a feature](https://github.com/Termix-SSH/Plugin-Security-Center/issues/new?template=feature_request.yml). Report an issue on the plugin's page in the Plugins tab fills in your versions for you.

Problems with Termix itself (login, hosts, credentials, sharing, sync) go in the [Termix repo](https://github.com/Termix-SSH/Termix/issues/new/choose). Not sure where it goes? Open it there and it will be moved.

Add as much detail as you can, in English if possible. For questions, join the [Discord](https://discord.gg/jVQGdvHDrf) server.

<br />

## License

Apache License 2.0. See [LICENSE](LICENSE).
