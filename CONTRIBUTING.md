# Contributing to Vulnyard

Thank you for considering a contribution! Bug reports, ideas, translations,
documentation fixes and code are all welcome.

## Before you start

- **Bugs and ideas:** open an issue first. For a bug, include the Vulnyard
  version (Settings → Environment), the Dependency-Track and GitLab versions and
  what you expected to happen. Never paste tokens, API keys or webhook URLs.
- **Security issues:** do not open a public issue – follow
  [SECURITY.md](SECURITY.md).
- **Larger changes:** describe the idea in an issue before writing the code, so
  that we can agree on the approach. The design is described in
  [`SPEC.md`](SPEC.md) (in Czech).

## Development setup

See [Development](README.md#development) in the README: Python 3.12+, Node 22,
git, Trivy and PostgreSQL. In short:

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
cd frontend && npm ci && npm run build && cd ..
export DATABASE_URL=postgresql://vulnyard:vulnyard@localhost:5432/vulnyard
uvicorn app.main:app --reload
```

Run the tests with a database they may empty:

```bash
export VULNYARD_TEST_DATABASE_URL=postgresql://vulnyard:vulnyard@localhost:5432/vulnyard_test
pytest
cd frontend && npm run build   # includes the TypeScript type check
```

## Ground rules

- **Code, identifiers, comments, commit messages and the API are in English.**
- **No user-facing text in the code.** Every text goes through the catalogues
  (`frontend/src/i18n/locales/<locale>.json`, `app/i18n/<locale>.json`). A new
  text goes into every shipped catalogue (`en` and `cs`); errors are codes with
  parameters, translated by the backend.
- **Nothing specific to one company or environment** in the code, the README or
  `SPEC.md` – such things are configured through environment variables.
- **Both build paths keep working:** `Dockerfile` / `docker-compose.yml` and
  `nixpacks.toml`. A change to dependencies or the build updates both.
- **Secrets never leave the server:** tokens and keys must not appear in logs,
  API responses or the frontend.
- **GitLab is called only from `app/services/sources/`**, the caller's identity
  is decided only in `app/auth.py`.
- **Dependency-Track endpoints** are checked against the instance's OpenAPI
  (`/api/openapi.json`); version-dependent features are switched on by the
  detected version.
- **Database changes** come with an Alembic migration (`alembic check` must
  pass).
- After changing `frontend/package.json`, run `npm install` and commit
  `package-lock.json`.

## License headers

Vulnyard is licensed under [Apache-2.0](LICENSE). Every new source file
(Python, TypeScript, shell, Dockerfile) starts with the header, as a comment in
that language:

```
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
```

By submitting a contribution you agree that it is licensed under Apache-2.0
(section 5 of the license). New bundled third-party binaries are listed in
[`NOTICE`](NOTICE).

## Translations

Adding a language takes two JSON files and no code – see
[Languages and translations](README.md#languages-and-translations). Partial
translations are welcome too: missing texts fall back to English. `pytest`
checks every catalogue for unknown keys and broken placeholders.

## Commit messages

Write the subject in English as a short imperative sentence – it ends up in
[`CHANGELOG.md`](CHANGELOG.md), which is generated from the history. Either
style works:

- a plain sentence: `Add bulk creation of targets`, `Fix the trend legend on
  narrow screens` – the first word decides the section (Add… → Added,
  Fix… → Fixed, Remove… → Removed, anything else → Changed);
- [Conventional Commits](https://www.conventionalcommits.org/):
  `feat(api): bulk-create targets`, `fix: …`, `feat!: …` for a breaking change.
  `chore:`, `docs:`, `test:`, `ci:`, `refactor:` are left out of the changelog.

To override the guess, add a trailer to the message, for example
`Changelog: fixed`. Accepted values: `added`, `changed`, `fixed`, `removed`,
`deprecated`, `security`, `breaking` and `skip` (leave the commit out). A
breaking change can also be marked with a `BREAKING CHANGE: …` footer.

## Pull requests

- Keep a pull request focused on one change, with tests for new behaviour.
- `pytest` and `npm run build` must pass.
- Describe what changed and why; link the issue it solves.

The project is developed in an upstream repository and published to GitHub as
snapshots. An accepted pull request is therefore applied upstream with you as
the author and arrives on GitHub with the next published version – the pull
request is then closed with a link to it, rather than merged on GitHub.
