<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="frontend/public/vulnyard-logo-dark.svg" />
    <img src="frontend/public/vulnyard-logo.svg" alt="Vulnyard" width="320" />
  </picture>
</p>

<p align="center">
  <strong>Central vulnerability scanning for your GitLab – no pipelines, no merge requests.</strong><br />
  GitLab → Trivy → CycloneDX SBOM → Dependency-Track → one dashboard for the whole organisation.
</p>

<p align="center">
  <a href="LICENSE"><img alt="License: Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" /></a>
  <img alt="Python 3.12+" src="https://img.shields.io/badge/python-3.12%2B-3776AB?logo=python&amp;logoColor=white" />
  <img alt="React 19" src="https://img.shields.io/badge/react-19-61DAFB?logo=react&amp;logoColor=black" />
  <img alt="Dependency-Track 4.12+" src="https://img.shields.io/badge/Dependency--Track-4.12%2B-4B5DA8" />
  <img alt="Trivy" src="https://img.shields.io/badge/scanner-Trivy-1904DA?logo=aqua&amp;logoColor=white" />
  <img alt="Docker" src="https://img.shields.io/badge/run%20with-Docker-2496ED?logo=docker&amp;logoColor=white" />
  <a href="#how-it-is-built"><img alt="Built with AI assistance" src="https://img.shields.io/badge/built%20with-AI%20assistance-8A2BE2" /></a>
</p>

<p align="center">
  <a href="https://vulnyard.eu">vulnyard.eu</a> ·
  <a href="#quick-start-docker">Quick start</a> ·
  <a href="CHANGELOG.md">Changelog</a> ·
  <a href="CONTRIBUTING.md">Contributing</a> ·
  <a href="SECURITY.md">Security</a> ·
  <b>English</b> · <a href="README.cs.md">Česky</a>
</p>

---

**Vulnyard** ([vulnyard.eu](https://vulnyard.eu)) centrally scans GitLab
repositories with [Trivy](https://github.com/aquasecurity/trivy), generates SBOMs
(CycloneDX) from them, uploads them to
[Dependency-Track](https://dependencytrack.org) and builds a clear dashboard for
DevOps on top of the results. Nothing is added to the scanned repositories – no
pipelines, no merge requests.

**Contents:** [Features](#features) · [How it works](#how-it-works) ·
[Quick start](#quick-start-docker) · [Configuration](#configuration) ·
[How scanning works](#how-scanning-works) · [Chat notifications](#chat-notifications) ·
[Ignoring vulnerabilities](#ignoring-vulnerabilities) · [API and tokens](#api-and-tokens) ·
[MCP](#mcp-for-coding-agents) · [Sign-in and security](#sign-in-and-security) · [Languages](#languages-and-translations) ·
[Development](#development) · [Contributing](#contributing) · [License](#license)

## Features

- **Scan targets** – a GitLab group (optionally including subgroups) or a single
  project. A new repository in a group is found automatically. For every target
  you choose the branches (the default branch by default), a schedule (cron),
  exclusions and a branch limit – and optionally **its own GitLab instance and
  token**, when the target lives elsewhere or you do not want one central token
  for everything.
- **Scanning** – shallow clone, Trivy, CycloneDX SBOM, upload to
  Dependency-Track, tags `vulnyard` and `source-group:<group>`. A project whose
  commit has not changed since the last scan is skipped.
- **Dashboard** – summaries by severity, trend (30/90/180 days), the riskiest
  projects, a project list with filters, project detail with findings and
  history, and an overview of vulnerabilities across projects ("where do we have
  CVE-XXXX?").
- **Threats** – the vulnerabilities to fix first: those attackers are known to
  exploit (the CISA KEV catalog, matched through aliases, so a GHSA finding counts
  too), those likely to be exploited soon (EPSS from Dependency-Track) and new
  critical or high ones. Ordered by that evidence rather than by severity alone.
- **Chat notifications** – after a scan that finds vulnerabilities, Vulnyard
  posts a message to a webhook (Google Chat) with the repository, finding counts
  by severity and the **repository maintainers**. The webhook is set globally and
  can be overridden per target when its messages should go to another space.
- **Ignoring vulnerabilities** – a vulnerability you will not act on can be
  suppressed by a rule for one target or for the whole application, optionally
  only for selected components (`pkg:npm/express@5.*`) and only until a given
  date. The suppression is sent to Dependency-Track as well.
- **Operations** – run history with errors per job, manual runs, cancelling a
  run, scheduler, history retention, connection tests in Settings.
- **MCP for coding agents** – developers ask from Claude Code, Cursor or VS Code
  ("what does this repository have, where do we use CVE-X?"); read-only.
- **REST API with tokens** – everything in the UI is available through the API,
  so another system can, for example, create scan targets on its own.
- **Multilingual interface** – Czech and English; another language is one
  translation file away.

## How it works

```mermaid
flowchart LR
    GL["GitLab<br/>groups and projects"] -- "discover, shallow clone" --> VY(["Vulnyard"])
    VY -- "Trivy → CycloneDX SBOM" --> DT[("Dependency-Track")]
    DT -- "findings and metrics" --> VY
    VY --> UI["Dashboard"]
    VY --> CH["Google Chat"]
    EXT["Other systems"] -- "REST API + token" --> VY
```

## Quick start (Docker)

```bash
cp .env.example .env          # and fill in the values you have
docker compose up --build     # application + PostgreSQL
```

The application runs at <http://localhost:8000>, the health check at `/health`.

If you do not have a Dependency-Track at hand, run one locally with the `dtrack`
profile:

```bash
docker compose --profile dtrack up --build
```

The Dependency-Track API then listens on `http://localhost:8081`, its UI on
`http://localhost:8082`. Create an API key in the UI (the default login is
`admin`/`admin`, DT forces a password change right away) and add
`DT_API_URL=http://dtrack-apiserver:8080`, `DT_UI_URL=http://localhost:8082` and
`DT_API_KEY=<key>` to `.env`.

### Running a released image

Every release is published as a container image for `linux/amd64` and
`linux/arm64` to `ghcr.io/oldsch00ler/vulnyard` (tags `X.Y.Z`, `X.Y` and
`latest`). A server needs no checkout – just `docker-compose.yml` and `.env`:

```bash
VERSION=X.Y.Z                 # the release to run
mkdir vulnyard && cd vulnyard
curl -fsSLO https://raw.githubusercontent.com/oldsch00ler/vulnyard/v$VERSION/docker-compose.yml
curl -fsSL -o .env https://raw.githubusercontent.com/oldsch00ler/vulnyard/v$VERSION/.env.example
# fill in .env, set POSTGRES_PASSWORD and VULNYARD_IMAGE=ghcr.io/oldsch00ler/vulnyard:$VERSION
docker compose pull
docker compose up -d --no-build
```

To upgrade, change the version in `VULNYARD_IMAGE` and run the last two commands
again; database migrations run on start. The bundled PostgreSQL keeps its data
in the `postgres-data` volume. `AUTH_MODE=none` does not authenticate anyone, so
on a reachable server put the application behind a VPN or an authenticating
proxy (see [Sign-in and security](#sign-in-and-security)).

## Configuration

All configuration goes through environment variables – the complete list with
descriptions is in [`.env.example`](.env.example). Some settings can be changed
in the UI (the Settings page) and then take precedence: scan concurrency, the
default cron, history retention, global exclusions and chat notifications.

| Variable | Meaning |
|---|---|
| `DATABASE_URL` | PostgreSQL connection (the only required one; `postgres://` and `postgresql://` both work) |
| `GITLAB_URL`, `GITLAB_TOKEN` | default repository source (self-hosted or gitlab.com); a target can have its own |
| `DT_API_URL`, `DT_API_KEY`, `DT_UI_URL` | Dependency-Track (API, key, links to the UI) |
| `AUTH_MODE`, `AUTH_HEADERS` | `none` (default) or `proxy-header` |
| `SCAN_CONCURRENCY`, `SCAN_TIMEOUT_SECONDS` | scan concurrency and the timeout of one scan |
| `TRIVY_BIN`, `TRIVY_OFFLINE` | path to Trivy and offline mode |
| `CA_BUNDLE` | PEM with a custom CA for HTTP calls, git and Trivy |
| `KEV_FEED_URL` | CISA catalog of known exploited vulnerabilities for the Threats page (default: the CISA feed); empty turns it off |
| `TZ`, `DEFAULT_LOCALE`, `LOG_LEVEL` | time zone, default language (`cs`, `en`, …), log level |

Only `DATABASE_URL` is required. Without the GitLab and Dependency-Track
variables the application starts normally, just shows a banner with the missing
configuration and scanning is disabled.

### A target's own GitLab and token

`GITLAB_URL` and `GITLAB_TOKEN` are the defaults. Every target can override
them:

- **token only** – the same instance, but a token limited to, say, one group,
- **URL and token** – a target on an entirely different GitLab instance (the
  token is then required).

One run can thus reach several instances at once, and the clone of each project
uses the token of its target. If every target has its own credentials,
`GITLAB_TOKEN` is not needed in the environment at all. The token is stored in
the database, **never returned to the API or the browser** (only a "set" flag)
and masked in the log. The target form has a "Test connection" button that
checks the instance and the token before saving.

### Required token permissions

- **GitLab:** a group access token on the topmost scanned group, role
  **Reporter**, scopes `read_api` + `read_repository`. A personal token is not
  needed. The token is also used for cloning over HTTPS.
- **Dependency-Track:** a team API key with the permissions `BOM_UPLOAD`,
  `PROJECT_CREATION_UPLOAD`, `VIEW_PORTFOLIO`, `VIEW_VULNERABILITY` and
  `PORTFOLIO_MANAGEMENT` (the last one is needed to add tags). The **Test
  connection** button in Settings checks that Dependency-Track is reachable and
  its version, but does not try the key's permissions – a missing permission
  shows up at the first scan, as an error listing what the key needs.

### Supported Dependency-Track versions

The minimum supported version is **4.12**, verified on **4.13** and **4.14**.
Below 4.12 scanning is not enabled and Settings explain why.

The Trivy version is pinned in
[`scripts/install-trivy.sh`](scripts/install-trivy.sh) and tied to the
Dependency-Track version through the CycloneDX format:

| Trivy | CycloneDX | Accepted by |
|---|---|---|
| 0.70.0 (default) | 1.6 | Dependency-Track 4.12 and newer |
| 0.71.0+ | 1.7 | Dependency-Track 4.14 and newer |

That is why 0.70.0 is the default. If all your instances run 4.14+, you can
upgrade Trivy – with a wrong combination the scan fails with a message that says
exactly that.

## How scanning works

For every target the application discovers projects and branches on its own.
Each project and branch is one job in the queue: a shallow clone
(`--depth 1 --single-branch`), Trivy generates a CycloneDX SBOM, which is
uploaded to Dependency-Track (`autoCreate`, the default branch is marked
`isLatest`), and the application waits until DT has processed it. The DT
project is named after the repository path, the version is the branch name. A
group target also gets a parent collection project that aggregates the metrics
of its children.

Vulnerability analysis is done by Dependency-Track, not Trivy – a new CVE thus
shows up even without a new scan. Clones are always deleted after the scan,
nothing is ever written to the repositories, and the summaries on the Overview
are counted from the default branch only, so that vulnerabilities from several
branches of the same repository do not add up.

## Chat notifications

In **Settings** you enable notifications, paste a Google Chat webhook and choose
the minimum severity (default "high"). A message is sent after every scan for
which Dependency-Track reports a finding of at least that severity, and it
contains:

```
*Vulnyard: vulnerabilities in `team/app`* (branch `main`)
critical: 2 · high: 5 · medium: 3
Scan target: Team
Repository maintainers: Jane Doe (@jdoe, Owner), John Smith (@jsmith, Maintainer)
Repository · Dependency-Track
```

The messages are in the language of `DEFAULT_LOCALE`.

**Who appears in the message:** people **added directly to the repository**
come first – Owners and Maintainers among them, and if there are none,
Developers. Members inherited from the group are used only when the project has
no members of its own at all, and the message then says so ("The repository has
no members of its own; group maintainers…"), because an inherited member is
typically not the author of the repository. Access token bot users are left
out. GitLab does not expose members' e-mails, so the message lists the name,
`@username`, role and a profile link – an `@` mention in Google Chat therefore
does not actually notify anyone.

**Threads:** all notifications about one repository (across branches) go to one
thread, not a new conversation. The application sends a `thread.threadKey`
derived from the repository path together with
`messageReplyOption=REPLY_MESSAGE_FALLBACK_TO_NEW_THREAD`: the first message
starts the thread, the following ones are added to it. This assumes a threaded
space ("Grouped by conversation topic"); in a flat space Google Chat ignores the
key and the messages simply follow each other.

**A target's own webhook:** the target form has an "Own chat webhook" field.
When filled in, the notifications of this target go there instead of the global
webhook – and they are sent even when the global switch is off. The webhook
contains a key and a token, so it is never returned to the browser or the log in
full, only shortened. A button sends a test message.

Besides the state, the message also says **what is new since the last scan**
("Since the last scan: critical +3"), so a deterioration can be told apart from
a repeated state.

**Improvements are reported too.** When a repository had findings above the
threshold and no longer has them after a fix, a "clean again" message arrives in
the same thread with the difference and whatever remains below the threshold –
otherwise a fixed repository would just go quiet, which looks the same as if
nobody scanned it. A repository that was already clean before generates no
message.

**When scanning itself breaks** (the GitLab token expires, Dependency-Track
rejects the key, Trivy disappears), a "scanning is failing" message arrives with
the reason and the run number – otherwise silence would look the same as "we
found nothing". This is reported only for errors that affect a whole run, not
for one odd repository, and the same problem at most once every six hours.

A chat failure never brings a scan down – a warning is logged and the run goes
on.

## Ignoring vulnerabilities

Not every finding can or must be fixed. A vulnerability can be marked as ignored
in **Vulnerabilities** (the "Ignore" button on a row) or in **Settings**, which
also lists all rules.

A rule has:

- **a scope** – one scan target, or the whole application,
- **a component pattern** – a glob over the purl. `*` means "this vulnerability
  anywhere in the scope", `pkg:npm/express@5.*` only express version 5. The form
  suggests the purls of components that actually have the vulnerability,
- **an analysis state for Dependency-Track** – "not affected", "false positive",
  "resolved",
- **a reason** – written to the analysis comment in DT, so it can be traced
  there as well,
- **valid until** – optional. After that day the rule stops holding and the
  suppression is reverted. Useful for "we are not dealing with it now, but let it
  come back in a month".

The suppression is **always sent to Dependency-Track** (`PUT /api/v1/analysis`),
even when the rule holds for one target only. The Overview, the trend chart and
the chat notifications read their counts from DT metrics, so a finding hidden
only in Vulnyard would still be counted there and the numbers would stop adding
up.

Rules are applied when saved, after every scan (a new scan brings new component
versions) and once a day, so that expiry takes effect. The operation is
idempotent and works both ways – whatever a rule no longer covers is
unsuppressed. When Dependency-Track is unavailable, the rule is saved anyway and
the next run sends it; it can be forced with the "Apply rules again" button.

## API and tokens

Everything the UI does is available through the REST API under `/api` –
interactive documentation (Swagger UI) is at **`/api/docs`**, the schema at
`/api/openapi.json`. Another system signs in to the API with an **API token**:

1. In **Settings → API tokens**, create a token: a name (who will use it), the
   permission **read only** or **read and write**, and optionally an expiry
   date.
2. The token is shown **only once** – save it right away in the system that will
   use it. The application keeps only its fingerprint (SHA-256), so it cannot be
   shown again; delete a lost token and create a new one.
3. Send it in the `Authorization: Bearer vy_…` header.

Example – an automation that creates a scan target when a new project appears in
GitLab (a token with write permission):

```bash
curl -X POST https://vulnyard.example.com/api/targets \
  -H "Authorization: Bearer $VULNYARD_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"kind": "project", "source_ref": "1234"}'
```

`source_ref` is the ID of the project (or of the group with `"kind": "group"`)
in GitLab; the application fills in the name and path itself. The other fields
(branches, cron, exclusions…) are optional and have the same defaults as the
form – see `/api/docs`. A duplicate target returns `409`, so a repeated call
breaks nothing.

Rules:

- changes made with a token are recorded in the audit fields (`updated_by`,
  `triggered_by`, `created_by`) as `token:<name>`,
- a "read only" token may only use `GET`, anything else gets `403` (the MCP
  endpoint is the exception: it only reads),
- an invalid, deleted or expired token gets `401`,
- tokens can be created and deleted only by a person in the UI, never by another
  token,
- tokens never appear in the log or in API responses (except the one at
  creation); the list shows only the first few characters, so they can be told
  apart.

The next section describes how tokens behave in the sign-in modes.

## MCP for coding agents

Developers can ask Vulnyard from their coding agent – Claude Code, Cursor, VS Code
and any other MCP client. The application serves an MCP endpoint at **`/mcp`**
(Streamable HTTP), so there is nothing to install: add the URL and a token.

It is **read-only by design**: no tool starts a scan, ignores a finding or
changes anything, whatever the token's permission. What the agent can ask:

| Tool | Answers |
|---|---|
| `list_projects` | Which repositories are scanned, with finding counts. |
| `project_findings` | Vulnerabilities of a repository, worst first, with the newer version of each component as an upgrade hint. The repository can be given as `group/project` or as its git remote URL. |
| `find_vulnerability` | Where we have a CVE (or GHSA…, aliases count): repositories, branches, components and versions, and whether it is known to be exploited. |
| `current_threats` | What to fix first – the same selection as the Threats page. |
| `scan_status` | When a repository was last scanned and why it failed. |

Every call needs an API token, even with `AUTH_MODE=none` – it is also the
record of who asked (`MCP … called by token <name>` in the log). Create one in
**Settings → API tokens**; **read only** is enough.

**Claude Code:**

```bash
claude mcp add --transport http vulnyard https://vulnyard.example.com/mcp \
  --header "Authorization: Bearer vy_…"
```

For a whole team, commit `.mcp.json` to the repository and let everyone keep
their token in an environment variable:

```json
{
  "mcpServers": {
    "vulnyard": {
      "type": "http",
      "url": "https://vulnyard.example.com/mcp",
      "headers": { "Authorization": "Bearer ${VULNYARD_TOKEN}" }
    }
  }
}
```

**Cursor** – `~/.cursor/mcp.json` (the token stays out of the repository):

```json
{
  "mcpServers": {
    "vulnyard": {
      "url": "https://vulnyard.example.com/mcp",
      "headers": { "Authorization": "Bearer vy_…" }
    }
  }
}
```

**VS Code** – `.vscode/mcp.json`; VS Code asks for the token and stores it
securely:

```json
{
  "inputs": [
    { "type": "promptString", "id": "vulnyard-token", "description": "Vulnyard API token", "password": true }
  ],
  "servers": {
    "vulnyard": {
      "type": "http",
      "url": "https://vulnyard.example.com/mcp",
      "headers": { "Authorization": "Bearer ${input:vulnyard-token}" }
    }
  }
}
```

Then just ask: *"Which vulnerabilities does this repository have and what should
I upgrade?"* or *"Do we use anything affected by CVE-2026-1234?"*

## Sign-in and security

- **`AUTH_MODE=none`** (default): the application does not sign anyone in –
  anyone who can reach it over the network has access. **Run it behind a VPN or
  an authenticating reverse proxy.** The UI and the log say so at every start.
- **`AUTH_MODE=proxy-header`**: the identity is set by an authenticating reverse
  proxy (oauth2-proxy, Authelia, Traefik forward-auth, corporate SSO). The
  backend reads the e-mail from the headers in `AUTH_HEADERS` (in that order)
  and records it for the audit of target changes and manually started runs. In
  this mode the application **must not be reachable outside the proxy** –
  otherwise anyone can forge the header.
- **API tokens** work in both modes. In `none` they are optional – the API stays
  open as before (the UI does not use tokens) and a token only says who made a
  change; the network still protects the API from outsiders. In `proxy-header` a
  valid token replaces the identity header – but the proxy must let requests
  with `Authorization: Bearer vy_…` through to the application, and if it lets
  them through without signing in, it must drop the `AUTH_HEADERS` headers sent
  by the client. An `Authorization` header with anything other than our token
  (such as a JWT the proxy passes on) is ignored.

Tokens stay on the server: the frontend never calls GitLab or Dependency-Track
directly, and tokens never appear in API responses or in the log (subprocess
output and HTTP call errors are masked). Subprocesses run without a shell, with a
timeout and cancellation; branch names are validated. The Settings page only
shows whether variables are set – never their values.

## Development

Prerequisites: Python 3.12+, Node 22 (see `frontend/.nvmrc`), git, Trivy and
PostgreSQL. The PostgreSQL from `docker-compose.yml` does not publish its port,
so run your own for development:

```bash
docker run -d --name vulnyard-db -p 5432:5432 \
  -e POSTGRES_USER=vulnyard -e POSTGRES_PASSWORD=vulnyard -e POSTGRES_DB=vulnyard \
  postgres:17-alpine
```

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
bash scripts/install-trivy.sh ./.bin          # Trivy with a verified checksum

cd frontend && npm ci && npm run build && cd ..
export DATABASE_URL=postgresql://vulnyard:vulnyard@localhost:5432/vulnyard
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Frontend in dev mode (proxying to the backend on port 8000):
`cd frontend && npm run dev`.

**Database:** migrations run on their own when the application starts
(`alembic upgrade head`). After changing the models, create a new migration
like this:

```bash
export DATABASE_URL=postgresql://vulnyard:vulnyard@localhost:5432/vulnyard
alembic revision --autogenerate -m "describe the change"
alembic check                 # verifies that models and migrations match
```

**Tests:** `pytest`. Tests that need a real PostgreSQL (the API over the
database) are skipped until you set a database they may write to (the tests
empty it before every test, so use a separate one, not the development one):

```bash
docker exec vulnyard-db createdb -U vulnyard vulnyard_test
export VULNYARD_TEST_DATABASE_URL=postgresql://vulnyard:vulnyard@localhost:5432/vulnyard_test
pytest
```

The application runs as a single instance – the scheduler and the worker are
part of the web process; horizontal scaling is not a goal of v1.

### Two build paths

The repository has both, and both must keep working:

- **Docker** – `Dockerfile`, `docker-compose.yml` (the default path),
- **nixpacks** – `nixpacks.toml` and `requirements.txt` in the root (platforms
  such as Coolify or Railway).

In both paths Trivy is installed by `scripts/install-trivy.sh`: the version is
pinned in the script and the downloaded archive is verified against its SHA256
checksum.

### Publishing to GitHub (maintainers)

Development happens upstream; GitHub gets snapshots. `scripts/publish-github.sh`
creates a commit on the `github` branch from `main` without the paths in
`.publishignore` and with a history of its own, so nothing
from the upstream history is ever published. Before committing it scans the
result (domains mentioned in excluded files, private keys, `.env` files) and it
installs a pre-push hook that lets only the `github` branch go to a github.com
remote.

```bash
scripts/publish-github.sh               # or: -m "Version 1.2" for the commit title
git push github github:main
```

### Releases and changelog (maintainers)

Versions follow [Semantic Versioning](https://semver.org/); a release is a
`vX.Y.Z` tag. [`CHANGELOG.md`](CHANGELOG.md) is generated from the commits since
the last release by `scripts/release.py`, which also bumps the version (backend
and frontend), commits and tags. Nothing is pushed.

```bash
scripts/release.py --dry-run            # preview the next version and its changelog
scripts/release.py                      # or: scripts/release.py 1.0.0
git push origin main vX.Y.Z
scripts/publish-github.sh               # snapshot + github/vX.Y.Z tag for GitHub
git push github github:main refs/tags/github/vX.Y.Z:refs/tags/vX.Y.Z
scripts/release.py notes vX.Y.Z         # body of the GitHub release
```

Pushing the `vX.Y.Z` tag to GitHub starts the *Container image* workflow
(`.github/workflows/image.yml`), which builds the image and publishes it to
`ghcr.io/oldsch00ler/vulnyard`. After the very first publication, make the
package public once in its settings on GitHub (Packages → vulnyard → Package
settings → Change visibility).

Where a commit lands in the changelog is decided by a `Changelog:` trailer
(`added`, `fixed`, `changed`, `removed`, `security`, `breaking`, `skip`…), a
Conventional Commits prefix (`feat:`, `fix:`, `feat!:`; `chore:`, `docs:`,
`test:`… are left out), or the first word of the subject ("Add …", "Fix …",
"Remove …"; anything else is Changed). See [CONTRIBUTING.md](CONTRIBUTING.md#commit-messages).

## Languages and translations

The interface, API error messages, the log and chat messages are available in
every language that has a catalogue. Right now that is **Czech** and
**English**.

- **The interface** picks its language with a switcher in the header (shown as
  soon as there are at least two languages) and remembers it in the browser.
  Without a choice, `DEFAULT_LOCALE` applies.
- **API errors** are in the language of the `Accept-Language` header. The
  interface sends the one you have chosen; other systems ask for a language the
  same way.
- **The log and chat messages** are always in the `DEFAULT_LOCALE` language,
  because several people read them at once.

### Adding a language

Adding a language takes **two files and no code**. Use English as the template
(the reference catalogue, always complete):

1. `frontend/src/i18n/locales/<language>.json` – interface texts. Copy
   `en.json` and translate the values. `language.name` is the language's name
   in that language ("Deutsch") – it is what the switcher shows.
2. `app/i18n/<language>.json` – backend messages (API errors, log, chat). Copy
   `en.json` and translate the values.

`<language>` is a BCP 47 code: `de`, `fr`, `pt-BR`… The application finds both
files on its own; after the frontend is built, the language appears in the
switcher and can also be set as `DEFAULT_LOCALE`.

Rules for translators:

- translate only the values, leave the keys unchanged,
- keep placeholders as they are: `{{count}}` in the frontend, `{count}` in the
  backend,
- plurals: in the frontend a key has the forms the language's rules require
  (`_one`, `_few`, `_many`, `_other`… – see
  [CLDR](https://www.unicode.org/cldr/charts/latest/supplemental/language_plural_rules.html)).
  English has only `_one` and `_other`, Czech also `_few` and `_many`,
- a catalogue does not have to be complete right away – missing texts show in
  English.

`pytest` (`tests/test_i18n.py`) checks every catalogue: that it has no unknown
keys (a typo), that no message lost a placeholder or added a foreign one, and
that the shipped catalogues (`cs`, `en`) are complete.

## How it is built

Vulnyard is developed with the help of AI coding tools, mostly Claude. The
design, the decisions and the review of every change are mine: generated code
goes through the same tests, review and release process as any other, and I am
responsible for what gets released.

## Contributing

Bug reports, ideas, translations and pull requests are welcome – see
[CONTRIBUTING.md](CONTRIBUTING.md). Found a security issue? Please report it
privately as described in [SECURITY.md](SECURITY.md), not in a public issue.

## License

Apache-2.0, see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>.
