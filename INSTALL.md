# Install Job Search 0.3.3-pilot.3

This MIT-licensed preparation-only prerelease targets macOS with a compatible local host. Python 3.10+ is needed for the project installer and optional helper; the helper uses POSIX file locking. Linux has not been tested for this release, and Windows or web/mobile-only installation is not accepted. Source download and successful copying do not prove host discovery.

## Git-backed marketplace

On a supported Codex CLI, register the public marketplace pinned to this release:

```sh
codex plugin marketplace add fxjim/job-search-plugin --ref v0.3.3-pilot.3
```

Then open the desktop Plugins Directory, select **Job Search Pilot**, and install **Job Search** from that source. The marketplace identifier is `job-search-pilot`; its catalog is `.agents/plugins/marketplace.json` and its plugin path is `./plugins/job-search`. Review the selected version/source before installing. On a CLI exposing plugin installation, the supported selector is:

```sh
codex plugin add job-search@job-search-pilot
```

Registration and plugin installation change the recipient's host configuration/cache and require their authorization and any enforced tool approvals. They do not connect Gmail/Upwork or grant application authority. Desktop setup may require a restart; schedule that with the user and preserve active work. Do not replace an existing marketplace of the same name without inspecting it first.

The source/ref syntax is documented in [OpenAI's packaging guidance](https://developers.openai.com/plugins/build/plugins) and was checked against the installed CLI help. This documentation and repository resolution are not an independent recipient installation test. No registration or install into the builder's working host is performed by publishing this release.

## Dedicated-project skill alternative

1. Download the [local ZIP](https://github.com/fxjim/job-search-plugin/releases/download/v0.3.3-pilot.3/job-search-0.3.3-pilot.3-local.zip) and [SHA256SUMS](https://github.com/fxjim/job-search-plugin/releases/download/v0.3.3-pilot.3/SHA256SUMS) from the [release](https://github.com/fxjim/job-search-plugin/releases/tag/v0.3.3-pilot.3). Verify the ZIP hash, extract it and keep its folder intact. The source ZIP contains the same source files under a different top-level folder.
2. Choose an existing dedicated project directory and a separate private data directory. Do not use your home/settings root or an unrelated project.
3. From the extracted folder, run `python3 scripts/install_skill.py --project /absolute/path/to/your/dedicated-project`, replacing the example path with your chosen project. A locally capable Dot may do this after you authorize that destination and its tool approvals; a chat without local execution cannot.
4. The installer copies exactly 18 files, including LICENSE, into `.agents/skills/job-search`, creates an install lock, and refuses a different existing copy. It does not change user-wide settings. Open a fresh conversation in the project and confirm actual host-supplied skill discovery. Use `$job-search` only where supported; stop and report a missing discovery result.

## First use, updates and removal

After plugin installation, type `@job` and select the intended Job Search source, or use its Try Now control where available. A selected chip alone is not proof of skill loading. Ask for guided setup for research/drafts only; provide your own evidence, then confirm the summary and private storage before saving. Start with fictional data using the [recipient checklist](plugins/job-search/ACCEPTANCE-CHECKLIST.md).

The release has no automatic update. Preserve records outside the package, compare a later release's checksum and use a new project for changed skill copies. For removal, delete only the confirmed project skill folder, or use the host's actual plugin uninstall control. These actions do not delete your separate data, chat history or backups. Never reset unrelated settings to repair discovery.

The plugin ZIP has root `plugin.json`; the local/source ZIPs are not plugin-ingestion ZIPs. Hosted ZIP import and official-directory installation are not accepted routes for this release. [Support](https://github.com/fxjim/job-search-plugin/issues) · [Privacy policy](https://github.com/fxjim/job-search-plugin/blob/v0.3.3-pilot.3/plugins/job-search/PRIVACY.md).
