# Vulnyard – specifikace pro implementaci

**Vulnyard** (https://vulnyard.eu) – slug `vulnyard` se používá pro repozitář, Docker image, Python balíček (`vulnyard`), název npm balíčku frontendu (`vulnyard-frontend`), prefixy a tagy.

Webová aplikace, která centrálně skenuje GitLab repozitáře (celé skupiny nebo jednotlivé projekty), pomocí Trivy z nich generuje SBOM (CycloneDX), nahrává je do Dependency-Tracku a nad výsledky zobrazuje přehledný dashboard pro DevOps engineery. Engineeři v aplikaci sami nastavují, co a kdy se skenuje. Do jednotlivých repozitářů se **nic nepřidává** (žádné pipeline).

Projekt je **soukromý open-source projekt** Lukáše Zuzaňáka (licence Apache-2.0, sekce 16), který musí jít provozovat kdekoli (Docker / docker-compose). Primárně se vyvíjí a provozuje v jednom konkrétním interním prostředí, jehož specifika jsou v samostatném souboru `SANDBOX.md`. **Tato specifikace nesmí obsahovat nic specifického pro konkrétní firmu nebo prostředí** – vše takové patří do `SANDBOX.md`.

> **Postup implementace:** po milnících v sekci 17. Každý milník musí jít nasadit a appka musí nastartovat oběma cestami (nixpacks i Docker, sekce 3). Pravidla v `SANDBOX.md` jsou pro nasazení do sandboxu závazná. Kde je napsáno „ověřit“, ověř proti skutečné instanci (OpenAPI Dependency-Tracku, GitLab API) a ne podle paměti.

---

## 1. Cíl a rozsah

**V rozsahu (v1):**
- Správa cílů skenování: GitLab skupina (volitelně včetně podskupin) nebo jednotlivý projekt, výběr větví (výchozí = default branch projektu, volitelně konkrétní větve nebo vzory), plán (cron), výjimky.
- Automatické zjišťování projektů ve skupinách přes GitLab API (nové repo ve skupině se skenuje samo). Podpora self-hosted GitLabu i gitlab.com.
- Skenování: mělký klon repa → `trivy fs` → CycloneDX SBOM → upload do Dependency-Tracku.
- Přeskočení projektů, jejichž commit se od posledního skenu nezměnil (Dependency-Track nové CVE vyhodnocuje sám průběžně nad uloženým SBOM).
- Dashboard: souhrn zranitelností, trend, nejrizikovější projekty, seznam projektů, detail projektu s nálezy, přehled zranitelností napříč projekty, historie běhů skenů a jejich chyby.
- Ruční spuštění skenu (cíl, projekt, vše).
- Notifikace do chatu přes webhook (sekce 9.5): po skenu, který najde zranitelnosti, zpráva s repozitářem, počty nálezů a maintainery. Globální webhook v nastavení, volitelně vlastní webhook u každého cíle.
- UI v češtině, připravené na další jazyky (sekce 15).

**Mimo rozsah (v1):** vlastní přihlašování (identita buď žádná, nebo z reverse proxy – sekce 13), úprava nálezů / auditování v Dependency-Tracku (dělá se přímo v DT, appka na něj odkazuje), skenování container image, jiné zdroje než GitLab (ale architektura je na ně připravená – sekce 2).

---

## 2. Architektura

```
                ┌────────────────────────────── Kontejner aplikace (jeden) ──────────────────────────────┐
                │                                                                                        │
 Prohlížeč ───► │  FastAPI (uvicorn, 0.0.0.0:$PORT)                                                      │
                │   ├─ /api/*        REST API pro frontend                                               │
                │   ├─ /health       health-check                                                        │
                │   ├─ /*            React SPA (statické soubory z frontend/dist)                        │
                │   ├─ Scheduler     APScheduler (cron cílů, denní snapshot, retence)                    │
                │   └─ Scan worker   asyncio fronta nad tabulkou scan_jobs                               │
                │         │  git clone --depth 1 → trivy fs → CycloneDX JSON (v dočasném adresáři)        │
                └─────────┼──────────────────────────────────────────────────────────────────────────────┘
                          │                    │                          │
                          ▼                    ▼                          ▼
                  Zdroj repozitářů       Dependency-Track API          PostgreSQL
                  (v1: GitLab API +      (upload BOM, metriky,         (DATABASE_URL)
                   git přes HTTPS)        nálezy)
```

Zásady:
- **Dependency-Track je zdroj pravdy o zranitelnostech.** Appka si ukládá jen konfiguraci, stav skenů, mapování projektů na DT UUID a denní snapshoty metrik pro trend.
- **Frontend nikdy nevolá GitLab ani Dependency-Track přímo.** Vše jde přes backend (tokeny zůstávají na serveru, žádné CORS).
- Jedna instance kontejneru – scheduler i worker běží v procesu webu. (Horizontální škálování není cíl v1; README to uvede.)
- **Přihlašovací údaje per cíl:** klienty zdroje vydává `SourceProvider` – pro cíl s vlastní URL/tokenem vytvoří (a cachuje) samostatného klienta, jinak použije údaje z prostředí. Jeden běh tak může sahat na víc instancí GitLabu a klon každého projektu používá token svého cíle.

**Abstrakce zdroje repozitářů:** veškerá komunikace s GitLabem je za rozhraním `RepositorySource` (vyhledání skupin/projektů, discovery projektů cíle, větve, poslední commit větve, sestavení autentizované clone URL, odkaz na repo ve webu). V1 má jedinou implementaci `GitLabSource`. Datový model má sloupec `source` (`gitlab`), aby šlo později přidat GitHub/Bitbucket bez migrace dat. Nic mimo `services/sources/` nesmí volat GitLab API přímo.

---

## 3. Nasazení a přenositelnost

Aplikace se řídí principy 12-factor: veškerá konfigurace přes ENV, žádný stav na disku, logy na stdout/stderr.

### 3.1 Obecná pravidla (platí pro každé prostředí)

1. Uvicorn poslouchá na `0.0.0.0` a portu z `PORT`, fallback `8000`: `uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}`.
2. **Každý commit do výchozí větve musí nastartovat.** Žádné placeholdery, na kterých kód spadne.
3. **Jen runtime konfigurace.** Frontend nesmí mít nic zapečeného při buildu (žádné `VITE_*` z prostředí). Runtime hodnoty (URL UI Dependency-Tracku, režim přihlášení, jazyk…) servíruje backend přes `/api/status`. Jeden build = jakékoli prostředí.
4. **Disk kontejneru je dočasný.** Trvalá data jen v PostgreSQL. Klony a SBOM soubory v dočasném adresáři (`TMPDIR`, výchozí `/tmp`) a vždy mazat.
5. **Migrace při startu**, idempotentně (Alembic `upgrade head` v lifespanu).
6. **Health-check** `GET /health` → `{"status":"ok"}` s `Cache-Control: no-store`, neprochází middlewarem pro statiku.
7. **Logy na stdout/stderr**, srozumitelné, s úrovní z `LOG_LEVEL`.
8. **Tajné hodnoty nikdy v repu.** `.env` v `.gitignore`, commitnout jen `.env.example` s názvy a popisem proměnných.
9. **Povinná je jen `DATABASE_URL`.** Bez ní appka skončí s jasnou hláškou. Chybí-li GitLab nebo Dependency-Track proměnné, appka **nastartuje**, zaloguje varování, skenování je vypnuté a UI zobrazí banner se seznamem chybějících proměnných.

### 3.2 Dvě build cesty

V repu jsou **obě** a musí zůstat funkční:

| Cesta | Soubory | Použití |
|---|---|---|
| nixpacks | `nixpacks.toml`, `requirements.txt` v kořeni | platformy typu Coolify/Railway (a interní sandbox, viz `SANDBOX.md`) |
| Docker | `Dockerfile`, `docker-compose.yml`, `.dockerignore` | kdekoli jinde, lokální vývoj, výchozí cesta v README |

Společné pro obě cesty je **`scripts/install-trivy.sh`**: verze Trivy natvrdo ve skriptu (`TRIVY_VERSION`, aktuální stabilní verze v době implementace – dohledat na GitHub Releases `aquasecurity/trivy`), stáhne `trivy_<ver>_Linux-64bit.tar.gz` (a ARM64 variantu podle `uname -m`) a `trivy_<ver>_checksums.txt`, ověří SHA256, rozbalí binárku do cílového adresáře (parametr skriptu, výchozí `./.bin`), spustí `trivy --version`. `set -euo pipefail`, při chybě build selže s jasnou hláškou. Upgrade Trivy = změna verze ve skriptu.

**nixpacks.toml:**
```toml
[phases.setup]
nixPkgs = ["...", "nodejs_22", "git", "curl"]

[phases.build]
cmds = [
  "bash scripts/install-trivy.sh ./.bin",
  "cd frontend && npm ci && npm run build"
]

[start]
cmd = "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"
```

**Dockerfile** (multi-stage):
1. `node:22-slim` – `npm ci && npm run build` ve `frontend/`.
2. `python:3.12-slim` – nainstalovat `git`, `ca-certificates`, `curl`; `scripts/install-trivy.sh /usr/local/bin`; `pip install -r requirements.txt`; zkopírovat `app/`, `alembic/`, `alembic.ini` a `frontend/dist` z první fáze.
3. Běh pod neprivilegovaným uživatelem, `EXPOSE 8000`, `HEALTHCHECK` na `/health`, `CMD` stejný start příkaz jako v nixpacks.

**docker-compose.yml:**
- služby `app` a `postgres` (volume pro data), `app` čte `.env`;
- volitelný profil `dtrack` (`docker compose --profile dtrack up`) s Dependency-Track API serverem a frontendem v pinnuté verzi ≥ 4.12, aby šlo vše vyzkoušet bez existující instance DT.

**Cesta k Trivy:** backend hledá binárku v pořadí `TRIVY_BIN` → `./.bin/trivy` (relativně ke kořeni aplikace) → `PATH`. Nenalezení = skenování vypnuté + hláška v UI a logu. Při startu logovat verze Trivy a gitu.

**Frontend build:** build nástroje (vite, typescript, tailwind, @types/*) v `dependencies`, ne `devDependencies` (některé platformy instalují jen produkční závislosti). `frontend/package-lock.json` v commitu (vytvořit `npm install`, nevymýšlet ručně). `.nvmrc` s `22` a `"engines": {"node": ">=20.9.0"}`.

---

## 4. Stack a struktura repozitáře

**Backend:** Python 3.12, FastAPI, SQLAlchemy 2 (async) + asyncpg, Alembic, pydantic-settings, httpx (async), APScheduler 3.x (AsyncIOScheduler).
**Frontend:** Vite + React + TypeScript, React Router, TanStack Query, Recharts, Tailwind CSS, react-i18next.

**Konvence:** kód, identifikátory, komentáře, názvy commitů a API v angličtině (budoucí open source). Texty pro uživatele (UI, chybové hlášky API, logy) česky, ale vždy přes katalogy textů (sekce 15), nikdy natvrdo v kódu komponent.

```
/
├─ LICENSE                   # Apache-2.0
├─ NOTICE                    # atribuce (Trivy je v Docker image)
├─ README.md                 # anglicky (úvodní stránka na GitHubu/GitLabu): co to je, rychlý start, konfigurace, tokeny
├─ README.cs.md              # totéž česky; obě verze držet v souladu
├─ CONTRIBUTING.md, SECURITY.md, .github/   # pro open source na GitHubu (pravidla, hlášení chyb, šablony)
├─ SPEC.md                   # tato specifikace
├─ SANDBOX.md                # specifika interního prostředí (na GitHub se nepublikuje, viz sekce 16)
├─ .publishignore            # co se nikdy nepublikuje na GitHub (sekce 16)
├─ CHANGELOG.md              # generuje scripts/release.py (sekce 16)
├─ requirements.txt
├─ nixpacks.toml
├─ Dockerfile, .dockerignore, docker-compose.yml
├─ .env.example, .gitignore
├─ scripts/install-trivy.sh
├─ alembic.ini, alembic/
├─ app/
│  ├─ main.py               # FastAPI app, lifespan (migrace, scheduler, worker, recovery)
│  ├─ config.py             # pydantic-settings, kontrola konfigurace
│  ├─ db.py, models.py, schemas.py
│  ├─ auth.py               # AUTH_MODE, získání identity
│  ├─ i18n/                 # katalogy hlášek backendu (cs.json), helper t(code, **params)
│  ├─ api/                  # routery: targets, projects, dashboard, runs, sources, settings, status
│  ├─ services/
│  │  ├─ sources/           # base.py (RepositorySource), gitlab.py (GitLabSource)
│  │  ├─ dtrack.py          # klient Dependency-Track API
│  │  ├─ scanner.py         # clone + trivy + upload, jeden job
│  │  ├─ queue.py           # worker, souběh, zrušení
│  │  ├─ scheduler.py       # cron úlohy
│  │  └─ snapshots.py       # denní snapshot metrik, retence
│  └─ static.py             # servírování frontend/dist + SPA fallback
├─ tests/                   # pytest: unit (vzory větví, maskování, discovery), API testy
└─ frontend/
   ├─ package.json, package-lock.json, .nvmrc, vite.config.ts, index.html
   ├─ public/            # logo, favicony, site.webmanifest (servírují se z kořene)
   └─ src/ (pages/, components/, api/, i18n/locales/cs.json)
```

---

## 5. Konfigurace (ENV)

| Proměnná | Povinná | Výchozí | Popis |
|---|---|---|---|
| `DATABASE_URL` | ano | – | PostgreSQL. Přijmout `postgres://` i `postgresql://` a převést na `postgresql+asyncpg://`. |
| `GITLAB_URL` | pro skenování | `https://gitlab.com` | Self-hosted i gitlab.com. Výchozí instance; cíl může mít vlastní. |
| `GITLAB_TOKEN` | pro skenování | – | Group/Project access token, role Reporter, scope `read_api`, `read_repository`. Výchozí token; cíl může mít vlastní, a pak není `GITLAB_TOKEN` potřeba. |
| `DT_API_URL` | pro skenování | – | Base URL API Dependency-Tracku (bez `/api/v1`) |
| `DT_API_KEY` | pro skenování | – | API klíč týmu v DT (oprávnění viz 9.1) |
| `DT_UI_URL` | ne | = `DT_API_URL` | URL frontendu DT pro odkazy |
| `AUTH_MODE` | ne | `none` | `none` \| `proxy-header` (sekce 13) |
| `AUTH_HEADERS` | ne | `X-Forwarded-Email,X-Forwarded-User` | Hlavičky s identitou pro `proxy-header`, v pořadí priority |
| `SCAN_CONCURRENCY` | ne | `2` | Počet paralelních skenů |
| `SCAN_TIMEOUT_SECONDS` | ne | `900` | Timeout jednoho skenu (klon + trivy) |
| `TRIVY_BIN` | ne | – | Explicitní cesta k Trivy (3.2) |
| `TRIVY_OFFLINE` | ne | `false` | `true` = `trivy fs --offline-scan` pro prostředí bez internetu |
| `CA_BUNDLE` | ne | – | Cesta k PEM s vlastní CA (GitLab/DT s interním certifikátem); použít pro httpx, git (`GIT_SSL_CAINFO`) i Trivy (`SSL_CERT_FILE`) |
| `TZ` | ne | `UTC` | Časová zóna scheduleru a zobrazení |
| `DEFAULT_LOCALE` | ne | `cs` | Výchozí jazyk UI a hlášek |
| `LOG_LEVEL` | ne | `INFO` | |

Konfigurace v DB (upravitelná v UI, sekce Nastavení) má přednost před výchozími hodnotami volitelných proměnných: souběh, výchozí cron, retence historie (výchozí 90 dní), globální vzory výjimek.

---

## 6. Datový model (PostgreSQL)

**`scan_targets`** – co se má skenovat
- `id` PK, `name` (zobrazovaný název), `source` (`gitlab`)
- `kind`: `group` | `project`
- `source_ref` (ID skupiny/projektu ve zdroji, string), `source_path` (full path, pro zobrazení)
- `source_url`, `source_token` nullable – **vlastní přihlašovací údaje cíle**; null = `GITLAB_URL` / `GITLAB_TOKEN` z prostředí. Cíl může být na jiné instanci, nebo mít token omezený jen na svou skupinu. Token je tajná hodnota (sekce 13): v API se vrací jen `source_token_configured`, nikdy hodnota.
- `include_subgroups` bool (default true)
- `branch_mode`: `default` | `custom` – **výchozí `default`** (skenuje se default branch každého projektu)
- `branch_patterns` text[] – jen při `custom`; názvy větví nebo glob vzory (např. `main`, `develop`, `release/*`)
- `include_default_branch` bool (default true) – při `custom` skenovat navíc i default branch
- `max_branches_per_project` int (default 10) – pojistka proti vzoru, který by trefil stovky větví
- `schedule_cron` nullable (null = jen ručně; výchozí `0 2 * * *`)
- `exclude_patterns` text[] (glob na cestu projektu, např. `*/archive-*`, `sandbox/*`)
- `skip_unchanged` bool (default true)
- `enabled` bool
- `dt_parent_uuid` nullable (UUID nadřazeného projektu v DT pro skupinu)
- `created_at`, `updated_at`, `updated_by` nullable (sekce 13)

**`projects`** – zjištěné projekty; jeden řádek = projekt + větev
- `id` PK, `source`, `source_project_id`, `path_with_namespace`, `name`, `web_url`, `default_branch`
- `branch`, unikátní (`source`, `source_project_id`, `branch`), `is_default_branch` bool
- `archived`, `empty_repo` bool, `excluded` bool (ruční výjimka z UI)
- `last_commit_sha`, `last_scanned_sha`, `last_scan_at`, `last_scan_status`
- `dt_project_uuid` nullable
- `first_seen_at`, `last_seen_at` (projekt/větev zmizelé z cíle se označí, nemažou se hned)

**`project_branch_overrides`** – volitelné přepsání výběru větví pro konkrétní projekt (má přednost před cílem)
- (`source`, `source_project_id`) PK, `branch_mode`, `branch_patterns`, `include_default_branch`, `updated_at`, `updated_by`

**`target_projects`** – M:N (jeden projekt může spadat pod víc cílů; skenuje se jednou)

**`scan_runs`** – jeden běh (ruční nebo plánovaný)
- `id`, `trigger`: `schedule` | `manual`, `target_id` nullable, `triggered_by` nullable
- `status`: `queued` | `running` | `done` | `failed` | `cancelled`
- `started_at`, `finished_at`, počty `total`, `succeeded`, `failed`, `skipped`

**`scan_jobs`** – jeden projekt+větev v běhu (zároveň fronta)
- `id`, `run_id`, `project_id`
- `status`: `queued` | `cloning` | `scanning` | `uploading` | `processing` | `done` | `skipped` | `failed` | `cancelled`
- `commit_sha`, `components_count`, `sbom_bytes`, `dt_upload_token`
- `error_code` + `error_params` (JSONB) – přeložitelná chyba (sekce 15), `error_detail` (technický text, bez tajných hodnot)
- `log_tail` (posledních ~50 řádků stderr, maskovaných)
- `queued_at`, `started_at`, `finished_at`, `duration_ms`

**`metric_snapshots`** – denní snapshot pro trend
- `date`, `project_id`, `critical`, `high`, `medium`, `low`, `unassigned`, `components`, `vulnerable_components`, `inherited_risk_score`, `suppressed`; unikátní (`date`, `project_id`)

**`ignore_rules`** – zranitelnosti, které se nebudou řešit (sekce 9.6)
- `vuln_id` (např. `CVE-2024-47764`), `purl_pattern` (glob nad purl komponenty, `*` = jakákoliv)
- `target_id` – NULL znamená celou aplikaci, jinak jen projekty toho cíle
- `analysis_state` (`NOT_AFFECTED` | `FALSE_POSITIVE` | `RESOLVED`), `reason`
- `expires_on` (NULL = dokud pravidlo někdo nesmaže), `created_at`, `created_by`

**`ignore_applications`** – co bylo z pravidla skutečně potlačeno v DT
- `rule_id`, `project_id`, `dt_project_uuid`, `dt_component_uuid`, `dt_vulnerability_uuid`, `purl`, `applied_at`
- Unikátní (`rule_id`, `dt_component_uuid`, `dt_vulnerability_uuid`). Dependency-Track se nedá zpětně zeptat „co potlačil Vulnyard“, takže se to eviduje tady – jinak by nešlo potlačení vzít zpět.

**`api_tokens`** – tokeny pro jiné systémy volající API (sekce 13)
- `name`, `token_hash` (SHA-256, unikátní), `token_prefix` (prvních 8 znaků pro rozlišení v UI), `scope` (`read` | `write`)
- `expires_on` (NULL = dokud token někdo nesmaže; platí včetně toho dne), `last_used_at` (obnovuje se nejvýš jednou za minutu), `created_at`, `created_by`
- Samotný token se neukládá; vrací se jen jednou, v odpovědi na jeho vytvoření.

**`settings`** – key/value (JSONB) pro globální nastavení.

---

## 7. Scan pipeline

### 7.1 Discovery (pro každý aktivní cíl před během)
1. `kind=group`: `GET /api/v4/groups/:id/projects?include_subgroups=<bool>&archived=false&with_shared=false&per_page=100&page=N` – stránkovat přes hlavičku `X-Next-Page`.
2. `kind=project`: `GET /api/v4/projects/:id`.
3. Vyřadit: `archived`, `empty_repo`, shodu s `exclude_patterns` cíle nebo globálními vzory, `projects.excluded = true`.
4. **Rozvinutí větví** (platí override projektu, jinak nastavení cíle):
   - `default` → jen `default_branch`.
   - `custom` → načíst větve projektu (`GET /api/v4/projects/:id/repository/branches?per_page=100`, stránkovat; u přesného názvu stačí `GET …/branches/:branch`), vybrat ty, které odpovídají `branch_patterns` (glob), přidat default branch, pokud `include_default_branch`. Omezit na `max_branches_per_project` (přednost default branch, pak podle data posledního commitu) a o oříznutí zalogovat varování.
   - Vzor, který v projektu nic netrefí, není chyba – v náhledu a v běhu se zobrazí jako „větev neexistuje, přeskočeno“.
5. Upsert do `projects` a `target_projects`, aktualizovat `last_seen_at`. Projekty/větve, které z cíle zmizely, přestat skenovat (v UI označit „už není v cíli“ / „větev už neexistuje“).

### 7.2 Detekce změn
- Pro každý projekt+větev `GET /api/v4/projects/:id/repository/branches/:branch` → `commit.id`.
- Pokud `skip_unchanged` a `commit.id == last_scanned_sha` a projekt má `dt_project_uuid` → job `skipped` (důvod „beze změny“). Ruční sken s volbou „vynutit“ přeskakování ignoruje.

### 7.3 Jeden sken (job)
Vše přes `asyncio.create_subprocess_exec` (nikdy `shell=True`), s timeoutem `SCAN_TIMEOUT_SECONDS`, v dočasném adresáři `<TMPDIR>/vulnyard-scan-<job_id>`, který se **vždy** smaže (`finally`).

1. **Klon:** `git clone --depth 1 --single-branch --branch <branch> --no-tags <clone_url> <dir>` s `GIT_TERMINAL_PROMPT=0`. Clone URL sestaví `RepositorySource` (pro GitLab `https://oauth2:<token>@<host>/<path>.git`). Submoduly nestahovat. Token maskovat ve všech logech a chybových hláškách.
2. **Trivy:** `trivy fs <dir> --format cyclonedx --output <soubor> --cache-dir <TMPDIR>/trivy-cache --skip-dirs .git --quiet --timeout <n>s` (+ `--offline-scan`, pokud `TRIVY_OFFLINE`). Bez `--scanners vuln` – SBOM obsahuje jen komponenty, analýzu dělá Dependency-Track (Trivy tak nepotřebuje svou DB).
3. **Kontrola SBOM:** validní JSON, `bomFormat == "CycloneDX"`, spočítat `components`. Prázdný SBOM není chyba, jen `components_count = 0`.
4. **Upload do DT** (9.2), uložit `dt_upload_token`, status `processing`.
5. **Čekání na zpracování:** polling `GET /api/v1/event/token/{token}` každé 3 s, max 10 min, dokud `processing == false`.
6. **Dohledání projektu:** `GET /api/v1/project/lookup?name=<name>&version=<branch>` → uložit `dt_project_uuid`, doplnit tagy (9.3), zavolat refresh metrik projektu.
7. Job `done`; na projektu `last_scanned_sha`, `last_scan_at`, `last_scan_status`.

### 7.4 Chyby
- Každý krok má vlastní `error_code` s parametry (např. `clone.branch_not_found {branch}`, `trivy.timeout {seconds}`, `dtrack.forbidden {permission}`) a technický `error_detail`.
- Chyba jednoho projektu neukončí běh. Běh je `done`, pokud doběhly všechny joby (i s chybami); `failed` jen při chybě discovery/konfigurace.
- HTTP volání na GitLab/DT: retry 3× s exponenciálním backoffem na 429/5xx/timeout.

---

## 8. Plánovač a fronta

- **Jen jedna instance plánuje.** Plánovač drží postgresový advisory lock; druhá
  instance ho nezíská, nezapne plánovač a jen loguje proč (jinak by každý cron
  zakládal dva běhy). Worker lock nepotřebuje – joby bere přes
  `FOR UPDATE SKIP LOCKED`, takže se práce mezi instance bezpečně rozdělí.
- **Fronta = tabulka `scan_jobs`.** Worker smyčka v lifespanu vybírá `queued` joby (`SELECT … FOR UPDATE SKIP LOCKED`), souběh omezený semaforem.
- **Deduplikace:** pokud projekt+větev už má job `queued` nebo běžící, nový nevytvářet.
- **Zrušení běhu:** `queued` joby → `cancelled`, běžící subprocesy ukončit (SIGTERM, po 10 s SIGKILL).
- **Recovery při startu:** joby ve stavech `cloning|scanning|uploading|processing` → `failed` s kódem `job.interrupted` („Přerušeno restartem aplikace“); běhy dopočítat. `queued` joby zpracovat. Smazat pozůstatky `<TMPDIR>/vulnyard-scan-*`.
- **Scheduler (APScheduler, časová zóna z `TZ`):**
  - pro každý `enabled` cíl s `schedule_cron` jedna úloha → vytvoří běh; při změně cíle v UI přeplánovat,
  - denní snapshot metrik (05:00) – 9.4,
  - denní retence – smazat běhy/joby starší než nastavená retence a snapshoty
    metrik starší než retence, ale nejméně 210 dní (nejdelší okno trendu je 180
    dní, takže kratší retence historie nesmí trend vyprázdnit),
  - `coalesce=True`, `max_instances=1`, `misfire_grace_time` ~1 h.

---

## 9. Integrace Dependency-Track

Hlavička `X-Api-Key`. **Minimální podporovaná verze: 4.12. Primární cílová verze: 4.13.x.** Endpointy a parametry ověřit proti OpenAPI instance (`<DT_API_URL>/api/openapi.json`). Verzi zjistit z `GET /api/version` a logovat při startu. Funkce vázané na verzi zapínat podle detekované verze (feature flags v `dtrack.py`) – na nepodporované verzi se funkce vypne a v Nastavení se zobrazí varování, appka nepadá. Pod 4.12 skenování odmítnout s jasnou hláškou.

Funkce 4.12+/4.13, které využít (ověřit v OpenAPI):
- **`isLatest`** při uploadu BOM – u default branch `isLatest=true`.
- **Kolekční projekty** – nadřazený projekt skupiny jako kolekce s agregací metrik z potomků (ideálně jen z latest verzí, pokud je volba dostupná).
- Tagy při uploadu (`projectTags`), pokud je parametr k dispozici; jinak úprava projektu po uploadu (9.3).

### 9.1 Oprávnění API klíče (tým v DT)
`BOM_UPLOAD`, `PROJECT_CREATION_UPLOAD`, `VIEW_PORTFOLIO`, `VIEW_VULNERABILITY`, `PORTFOLIO_MANAGEMENT`. Stránka Nastavení má tlačítko „Otestovat připojení“ (chyby 401/403 přeložit na lidskou hlášku s chybějícím oprávněním).

### 9.2 Pojmenování a upload
- **Název projektu v DT** = cesta projektu ve zdroji (`path_with_namespace`), **verze** = větev.
- **Hierarchie:** pro cíl typu skupina zajistit nadřazený projekt v DT s názvem = full path skupiny (dohledat, případně založit), UUID uložit do `scan_targets.dt_parent_uuid`.
- **Upload:** `POST /api/v1/bom` jako `multipart/form-data`: `projectName`, `projectVersion`, `autoCreate=true`, `parentUUID` (pokud je), `isLatest` (true jen pro default branch), `bom`. Odpověď obsahuje `token`.
- Každá větev = samostatná verze projektu v DT. **Souhrny, trend a top projekty se počítají jen z default branch**, aby se zranitelnosti z více větví téhož repa nesčítaly. Ostatní větve jsou vidět v detailu projektu a v tabulce Projekty přes filtr „Větev: default / všechny“.

### 9.3 Tagy
Každému projektu tag `vulnyard` a `source-group:<full path top-level skupiny>`. Pokud tagy nejdou poslat při uploadu, upravit projekt po uploadu (`PATCH /api/v1/project/{uuid}` – ověřit); tagy **sloučit** s existujícími, ne přepsat. Tag `vulnyard` odlišuje „naše“ projekty od ostatních v DT.

### 9.4 Čtení dat
- Metriky projektu: `GET /api/v1/metrics/project/{uuid}/current`, historie `…/days/{n}`, refresh `…/refresh`.
- Nálezy projektu: `GET /api/v1/finding/project/{uuid}?suppressed=false`.
- Detail projektu: `GET /api/v1/project/{uuid}`.
- Nálezy napříč portfoliem: `GET /api/v1/finding/grouped` **nemá filtr na projekt** a odpovídá za celou instanci. Na sdíleném Dependency-Tracku by souhrn zranitelností ukazoval cizí projekty, proto se **skládá z per-projektových nálezů** (`/finding/project/{uuid}`) jen pro projekty, které máme jako cíl, a seskupení, filtrování i stránkování dělá aplikace.
- **Denní snapshot:** pro každý projekt s `dt_project_uuid` uložit current metriky do `metric_snapshots`. Trend se počítá z této tabulky. Při prvním spuštění lze snapshoty zpětně doplnit z `/days/{n}`.
- **Cache:** odpovědi DT pro dashboard v paměti procesu (TTL 60 s), po skenu cache projektu zneplatnit.
- Odkazy do DT UI: `<DT_UI_URL>/projects/<uuid>`, zranitelnost `<DT_UI_URL>/vulnerabilities/<source>/<vulnId>`.

### 9.5 Notifikace do chatu

Po každém úspěšném skenu, u kterého Dependency-Track hlásí nález alespoň nastavené
závažnosti, pošle aplikace zprávu na webhook chatu (formát Google Chat: `POST`
s `{"text": …}`, formátování `*tučně*`, `` `kód` ``, `<url|popis>`).

- **Obsah zprávy:** cesta repozitáře a větev, počty nálezů podle závažnosti, cíl
  skenování, **maintaineři repozitáře** a odkazy do zdroje a do Dependency-Tracku.
- **Kdo je odpovědný za repo:** přednost mají **členové přidaní přímo k projektu**
  (`GET /projects/:id/members`) – to jsou lidé, kteří repo skutečně vlastní.
  Z nich se bere nejodpovědnější úroveň: Owner a Maintainer (≥ 40), a pokud takový
  nikdo není, Developeři (≥ 30). Teprve když projekt nemá vlastní členy vůbec,
  použijí se zdědění ze skupiny (`GET /projects/:id/members/all`, jen ≥ 40) a
  zpráva to **explicitně řekne** – zděděný člen není autor repa. Ověřeno na reálné
  instanci: 22 z 25 vzorkovaných projektů má vlastní členy, zatímco zděděné
  skupiny mají 80–100 členů, kteří s projektem nemají nic společného.
  Uživatelé pro přístupové tokeny (`project_*_bot`, `group_*_bot`) se vynechávají.
  GitLab e-maily členů nevydává, proto se používá jméno, `@username`, role a odkaz
  na profil.
- **Vlákna:** zpráva nese `thread.threadKey` odvozený z cesty repozitáře a posílá se
  s `messageReplyOption=REPLY_MESSAGE_FALLBACK_TO_NEW_THREAD`, takže všechna
  oznámení o jednom repu (i z různých větví) drží v jednom vlákně a nezakládají
  novou konverzaci. Funguje to v prostorech s vlákny; v plochém prostoru Google
  Chat klíč ignoruje.
- **Nastavení:** globální přepínač, globální webhook a minimální závažnost
  (výchozí `high`) v Nastavení; u každého cíle volitelně **vlastní webhook**,
  který má přednost a posílá i při globálně vypnutých notifikacích.
- **Webhook je tajná hodnota** (obsahuje klíč a token): ukládá se v DB, do API a
  UI se vrací jen zkrácený, v logu se maskuje.
- **Co je nového:** zpráva vedle stavu uvádí i rozdíl proti předchozímu skenu
  („kritické +3"). Počty z posledního skenu se ukládají do `projects.last_metrics`,
  takže srovnání nezávisí na denních snapshotech.
- **Zlepšení se hlásí taky:** když repo dřív mělo nálezy nad nastavenou hranicí
  a teď už je nemá, přijde zpráva „je zase čisté" s rozdílem a s tím, co zbývá
  pod hranicí. Bez toho by se spravené repo prostě odmlčelo, což je k nerozeznání
  od toho, že ho nikdo neskenuje. Repo, které bylo čisté i předtím, mlčí dál.
- **Rozbité skenování:** když běh selže na systémové chybě (odmítnutý token,
  nedosažitelný Dependency-Track, chybějící Trivy…) a nejde jen o jeden projekt,
  pošle se zpráva „skenování se nedaří" s důvodem a číslem běhu, ve vlastním
  vlákně. Stejný problém se hlásí nejvýš raz za 6 hodin, jiný problém vždy.
- Selhání chatu **nikdy neshodí sken** – zaloguje se varování.

---

### 9.6 Ignorování zranitelností

Zranitelnost, kterou se tým rozhodl neřešit, se dá označit pravidlem. Pravidlo drží
aplikace (Dependency-Track žádné vzory neumí) a rozpadá ho na jednotlivé nálezy.

- **Rozsah:** buď jeden cíl skenování (platí pro jeho projekty), nebo celá aplikace.
- **Vzor komponenty:** glob nad purl, například `pkg:npm/express@5.*`. Výchozí `*`
  znamená „tato zranitelnost kdekoliv v rozsahu“.
- **Platnost:** nepovinné datum „do kdy“. Po něm pravidlo přestane platit a potlačení
  se zruší; řádek pravidla zůstává jako historie. Datum v minulosti se odmítá – je to
  překlep, ne přání.
- **Potlačení se posílá do Dependency-Tracku** (`PUT /api/v1/analysis` s `project`,
  `component`, `vulnerability`, `isSuppressed` a komentářem, který říká, ze kterého
  pravidla to je), a to **u obou rozsahů**. Přehled, trend i notifikace čtou metriky
  z DT, takže nález skrytý jen lokálně by se tam dál počítal a čísla by si přestala
  odpovídat.
- **Kdy se pravidla aplikují:** při vytvoření a změně pravidla, po každém úspěšném
  skenu projektu (nový sken přináší nové verze komponent) a jednou denně (aby se
  projevila expirace i u projektu, který se ten den neskenoval). Operace je
  idempotentní a funguje oběma směry: co pravidlo přestalo pokrývat, se odpotlačí.
- **Metriky v DT se přepočítávají asynchronně**, takže po potlačení se na ně krátce
  a omezeně počká – jinak by oznámení do chatu hlásilo zranitelnost, kterou někdo
  právě označil za ignorovanou.
- Selhání Dependency-Tracku pravidlo nezruší: rozhodnutí je uložené a další běh ho
  dopošle.

---

## 10. Integrace GitLab (`GitLabSource`)

Hlavička `PRIVATE-TOKEN`, base `<GITLAB_URL>/api/v4`.

| Účel | Endpoint |
|---|---|
| Vyhledání skupin | `GET /groups?search=<q>&per_page=20` |
| Detail skupiny | `GET /groups/:id` |
| Projekty skupiny | `GET /groups/:id/projects?include_subgroups=true&archived=false&with_shared=false&per_page=100` |
| Vyhledání projektů | `GET /projects?search=<q>&membership=true&per_page=20` |
| Detail projektu | `GET /projects/:id` |
| Poslední commit větve | `GET /projects/:id/repository/branches/:branch` |
| Seznam větví | `GET /projects/:id/repository/branches?search=<q>&per_page=100` |
| Maintaineři projektu | `GET /projects/:id/members/all?per_page=100` (access level ≥ 40) |

Doporučený token (README): group access token na nejvyšší skenované skupině (role Reporter, scope `read_api` + `read_repository`), ne osobní token. Na gitlab.com funguje stejně.

---

## 11. REST API aplikace

JSON. Chyby ve tvaru `{"error": {"code": "...", "params": {...}, "message": "přeložený text"}}` (sekce 15).

**Systém**
- `GET /health`
- `GET /api/status` – stav konfigurace (chybějící proměnné), dosažitelnost zdroje a DT, verze DT a Trivy, stav scheduleru a workeru, runtime konfigurace pro frontend (`dt_ui_url`, `source_url`, `auth_mode`, `default_locale`, `available_locales`)
- `GET /api/me` – identita podle `AUTH_MODE` (jinak `{"email": null}`)

**Cíle skenování**
- `GET/POST /api/targets`, `GET/PUT/DELETE /api/targets/{id}`
- `POST /api/targets/preview` – discovery bez uložení, vrací projekty a větve a co by bylo vyřazeno a proč
- `POST /api/targets/{id}/scan?force=false`
- `POST /api/targets/{id}/test-source` – ověří instanci a token, které cíl používá

**Zdroj (našeptávače)**
- `GET /api/source/groups?search=`, `GET /api/source/projects?search=`, `GET /api/source/projects/{id}/branches?search=`
- `POST /api/source/groups`, `POST /api/source/projects`, `POST /api/source/test` – totéž, ale s volitelnými údaji (`source_url`, `source_token`) v těle, aby šlo vybírat skupinu na jiné instanci ještě před uložením cíle. Token nikdy nejde v query stringu.

**Projekty**
- `GET /api/projects?target_id=&search=&min_severity=&status=&branch=default|all&sort=&page=` (výchozí `branch=default`)
- `GET /api/projects/{id}`, `GET /api/projects/{id}/findings`, `GET /api/projects/{id}/history`
- `PATCH /api/projects/{id}` (`excluded`), `POST /api/projects/{id}/scan?force=true`
- `GET/PUT/DELETE /api/projects/{id}/branch-override`

**Dashboard**
- `GET /api/dashboard/summary`, `GET /api/dashboard/trend?days=30|90|180&target_id=`, `GET /api/dashboard/top-projects?limit=10`
- `GET /api/dashboard/by-target?days=30|90|180` – souhrn za každý cíl včetně změny za okno

**Zranitelnosti**
- `GET /api/vulnerabilities?min_severity=&search=&branch=default|all`

**Běhy**
- `GET /api/runs?page=`, `GET /api/runs/{id}`, `POST /api/runs/{id}/cancel`, `POST /api/runs` (skenovat vše)

**Nastavení**
- `GET/PUT /api/settings`, `POST /api/settings/test-source`, `POST /api/settings/test-dtrack`

**API tokeny** (jen pro lidi – request s tokenem sem dostane 403)
- `GET /api/tokens`, `POST /api/tokens` (`name`, `scope` = `read` | `write`, `expires_on`) – odpověď obsahuje `token`, jedinkrát
- `DELETE /api/tokens/{id}`

Dokumentace API (Swagger UI) je na `/api/docs`, schéma na `/api/openapi.json`.

---

## 12. Frontend

Levé menu, v hlavičce indikátor běžícího skenu, banner při chybějící konfiguraci a varování při `AUTH_MODE=none`. Barvy závažnosti: critical červená, high oranžová, medium žlutá, low modrá, unassigned šedá (vždy i s textem). Světlý i tmavý režim podle systému. TanStack Query; stránky s běžícím skenem se obnovují každých 5 s. Veškeré texty přes `t()` (sekce 15).

1. **Přehled** – karty se součty podle závažnosti a počtem zranitelných projektů; graf trendu (stacked area, 30/90/180 dní); top 10 nejrizikovějších projektů; panel „Stav skenování“ (poslední běh, chyby za 24 h, příští plánovaný běh).
2. **Projekty** – tabulka: projekt, cíl, větev, C/H/M/L badge, risk score, poslední sken, odkazy do zdroje a DT. Filtry: cíl, text, minimální závažnost, stav skenu, větev (default/všechny). Řazení.
3. **Detail projektu** – metriky a odkazy; přepínač větví (výchozí default branch); tlačítka „Skenovat teď“, „Vyloučit ze skenování“, „Nastavit větve pro tento projekt“ (override, s návratem na nastavení cíle); tabulka nálezů (vulnId, závažnost, CVSS, EPSS, komponenta@verze, purl, stav analýzy); mini trend; historie skenů s chybami.
4. **Zranitelnosti** – **jen naše projekty** (sekce 9.4), seskupeno podle CVE/GHSA, rozbalením zasažené projekty a verze komponent („kde všude máme CVE-XXXX?“). U každé zranitelnosti tlačítko **„Ignorovat“** (sekce 9.6) s předvyplněným id a našeptanými purl komponent; přepínač „Zobrazit i ignorované“ a označení ignorovaných.
5. **Cíle skenování** – seznam cílů (typ, cesta, větve, plán lidsky „denně ve 2:00“, počet projektů, stav, přepínač enabled). Formulář: typ s našeptávačem ze zdroje, podskupiny, **větve** – „Default branch (doporučeno)“ / „Vlastní výběr“ (chipy s názvy/vzory, u projektu našeptávač skutečných větví, „Skenovat i default branch“, limit větví), cron s předvolbami a vlastním výrazem, vzory výjimek, přeskakovat beze změny. Tlačítka **„Náhled projektů“** a „Spustit sken“.
6. **Běhy skenů** – historie běhů; detail s joby, stavem a chybou/logem; zrušení.
7. **Nastavení** – stav připojení s testy, verze Trivy a DT (varování u nepodporované), souběh, výchozí cron, retence, globální výjimky, notifikace do chatu, **pravidla ignorace** (seznam s rozsahem, vzorem, platností a počtem potlačených nálezů; přidání, smazání, „Aplikovat znovu“), přehled ENV jen jako nastaveno/chybí.

---

## 13. Bezpečnost a identita

- **`AUTH_MODE=none`** (výchozí): bez identity. Appka musí být provozována za VPN nebo jinak chráněná – UI i log při startu zobrazí varování. README to uvede výrazně.
- **`AUTH_MODE=proxy-header`**: identitu nastavuje autentizující reverse proxy (oauth2-proxy, Authelia, Traefik forward-auth, firemní SSO…). Backend čte e-mail z hlaviček v `AUTH_HEADERS` (v pořadí), jen na serveru. Chybí-li hlavička, API vrací 401. Identita se nikdy nebere z těla requestu ani od frontendu. README upozorní, že appka nesmí být v tomto režimu dosažitelná mimo proxy (jinak si hlavičku může kdokoli podvrhnout).
- **API tokeny** pro jiné systémy (např. automat, který založí cíl, když vznikne nový projekt). Vytváří je člověk v Nastavení; posílají se jako `Authorization: Bearer vy_…` a fungují v obou režimech:
  - Token má prefix `vy_` a 32 náhodných bajtů; ukládá se jen SHA-256. Bearer bez prefixu `vy_` se ignoruje (proxy může posílat dál vlastní JWT), takže requesty bez našeho tokenu se chovají přesně jako dřív.
  - Neplatný, smazaný nebo prošlý token → 401 s `WWW-Authenticate: Bearer`. Token `read` smí jen `GET`/`HEAD`/`OPTIONS`, jinak 403. Tokeny nejde spravovat tokenem (`/api/tokens` → 403).
  - S platným tokenem je identita `token:<název>`; v `proxy-header` režimu se pak hlavička s identitou nevyžaduje (proxy musí takové requesty pustit dál).
  - V režimu `none` je token nepovinný – API zůstává otevřené jako dřív a token jen určuje identitu pro audit. Ochranu API v tomto režimu dál zajišťuje síť (VPN).
- V obou režimech se identita (pokud je) ukládá do `updated_by`/`triggered_by` pro audit.
- Žádný vlastní login v v1; architektura nesmí bránit pozdějšímu OIDC (identita jen přes `auth.py`).
- Tokeny jen v ENV, nikdy ve frontendu, v API ani v logu (maskovací funkce na výstupy subprocesů a chyby httpx s URL).
- Subprocesy bez shellu, argumenty jako seznam; cesty a větve validovat (větev nesmí začínat `-`, povolené znaky).
- Klony se nikdy nespouštějí ani nebuildí – jen se čtou soubory Trivy.

---

## 14. Logování a provoz

- Při startu: verze aplikace, Trivy, gitu a DT, stav konfigurace, režim přihlášení, počet naplánovaných cílů.
- Každý job loguje začátek/konec/chybu s cestou projektu, větví a dobou trvání.
- Hlášky o chybné konfiguraci říkají, co a kde opravit.

---

## 15. Vícejazyčnost (i18n)

Aplikace obsahuje **češtinu a angličtinu**. Přidání dalšího jazyka znamená jen přidat dva překladové soubory – žádnou změnu kódu (viz README, „Jak přidat jazyk“).

- **Referenční katalog je angličtina** (`en`): vždy kompletní, je vzorem pro překlady a chybějící text v jiném jazyce se vezme z něj. Komunitní katalog tak nemusí být hned kompletní. Dodávané katalogy (`cs`, `en`) kompletní být musí.
- **Frontend:** react-i18next, texty v `frontend/src/i18n/locales/<locale>.json` (klíče podle stránek, např. `targets.form.branchMode.default`). Katalogy se načítají automaticky (`import.meta.glob`), každý nese svůj název v `language.name`. Žádné natvrdo psané texty v komponentách. Formátování dat, čísel, jednotek a relativního času přes `Intl` s aktuálním locale. Pluralizace přes i18next (tvary `_one`, `_few`, `_many`, `_other`… podle CLDR daného jazyka). Jazyk: uložený výběr uživatele (localStorage) → `default_locale` z `/api/status`. Přepínač jazyka v hlavičce se zobrazí, jakmile jsou aspoň dva jazyky; po přepnutí se znovu načtou data, protože část textů renderuje backend.
- **Backend:** chyby a stavy jako **kódy s parametry** (`error_code`, `error_params`), přeložený `message` se sestaví z katalogu `app/i18n/<locale>.json` podle `Accept-Language` (fallback `DEFAULT_LOCALE`). Frontend posílá `Accept-Language` podle zvoleného jazyka. Dostupné jazyky = soubory v `app/i18n` (bez seznamu v kódu). Do DB se ukládají kódy, ne texty – historie se tak po přepnutí jazyka zobrazí správně.
- **Logy a zprávy do chatu:** přes stejný katalog (helper `t()`) v jazyce `DEFAULT_LOCALE` – čte je víc lidí najednou.
- Test (pytest) ověří, že všechny klíče použité v kódu existují v referenčním katalogu, a u každého katalogu, že nemá neznámé klíče a nepřišel o placeholder ani nepřidal cizí.

---

## 16. Open source a licence

- **Licence Apache-2.0.** Autor a držitel autorských práv: **Lukáš Zuzaňák** (soukromá osoba), `lukas@zuzanak.eu`, https://zuzanak.eu, https://zulustudio.eu.
- `LICENSE` (nezměněný text Apache-2.0) a `NOTICE` (copyright autora + atribuce Trivy) jsou v repu od prvního commitu – **neupravovat `LICENSE`**, copyright patří do `NOTICE`.
- Hlavička každého zdrojového souboru (Python, TS/TSX, shell, Dockerfile):
  ```
  # SPDX-License-Identifier: Apache-2.0
  # Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
  ```
  (v TS/TSX jako `//` komentáře; JSON a Markdown bez hlavičky).
- Metadata: `frontend/package.json` → `"license": "Apache-2.0"`, `"author": "Lukáš Zuzaňák <lukas@zuzanak.eu> (https://zuzanak.eu)"`, `"homepage": "https://vulnyard.eu"`, `"private": true` (balíček se nepublikuje na npm). Dockerfile → OCI labely `org.opencontainers.image.licenses="Apache-2.0"`, `org.opencontainers.image.authors="Lukáš Zuzaňák <lukas@zuzanak.eu>"`, `org.opencontainers.image.url="https://vulnyard.eu"`, `org.opencontainers.image.title="Vulnyard"`, `org.opencontainers.image.description="Centrální skenování GitLab repozitářů přes Trivy a Dependency-Track"`. Patička UI: „Vulnyard · Apache-2.0 · © Lukáš Zuzaňák“ s odkazy na https://vulnyard.eu a web autora (text přes i18n katalog). Název aplikace v UI, `<title>`, README a logu při startu: „Vulnyard“.
- Docker image musí obsahovat `LICENSE` a `NOTICE` (zkopírovat do image, např. `/app/`).
- **Vývoj žije na GitLabu, GitHub je veřejná kopie.** Na GitHub jde jen větev `github`, kterou vytváří `scripts/publish-github.sh`: každý běh = jeden commit se stromem z `main` bez cest z `.publishignore` (`SANDBOX.md`), s vlastní historií – historie `main` se tak ven nikdy nedostane. Skript před vytvořením commitu prohledá publikovaný obsah: domény zmíněné ve vyloučených souborech, privátní klíče a soubory jako `.env` publikaci zastaví. Nainstaluje i pre-push hook, který na remote s `github.com` pustí jen větev `github` (ne `main`, ne tagy) a commity zkontroluje znovu. Větev `github` se nikdy needituje ručně; pull requesty z GitHubu se přebírají do `main` (s autorem) a ven jdou dalším snapshotem.
- **Verzování a changelog:** sémantické verze, vydání = tag `vX.Y.Z` na `main`. Jediný zdroj verze je `app/__init__.py` (`__version__`); `scripts/release.py` ji při vydání zapíše i do `frontend/package.json` a lock souboru, vygeneruje sekci `CHANGELOG.md` (formát Keep a Changelog) z commitů od posledního tagu, commitne a otaguje. Zařazení commitu: trailer `Changelog:` → prefix Conventional Commits → první slovo předmětu (Add/Fix/Remove…). Další verze se odvodí (breaking → major, Added → minor, jinak patch), jde zadat i ručně. Publikační skript k snapshotu vydání vytvoří lokální tag `github/vX.Y.Z`, který se na GitHub pushuje jako `vX.Y.Z`; `scripts/release.py notes vX.Y.Z` vypíše text pro GitHub Release. Test hlídá, že verze sedí ve všech souborech i v changelogu.
- CI a publikace image na GHCR se řeší později.
- README (`README.md` anglicky, `README.cs.md` česky): co to je, screenshot, rychlý start přes `docker compose --profile dtrack up`, tabulka konfigurace, potřebná oprávnění tokenů, režimy přihlášení a bezpečnostní upozornění, podporované verze DT.

---

## 17. Milníky

1. **Kostra** – FastAPI + `/health` + `/api/status`, React shell s navigací a i18n (cs), `LICENSE`, `NOTICE`, `install-trivy.sh`, `nixpacks.toml`, `Dockerfile`, `docker-compose.yml`, `.env.example`, log verzí při startu, banner chybějící konfigurace. Ověřit obě build cesty.
2. **DB a cíle** – modely, Alembic migrace při startu, `RepositorySource` + `GitLabSource`, CRUD cílů včetně výběru větví, našeptávače, náhled discovery.
3. **Skenování** – fronta a worker, klon + Trivy + upload + polling + lookup + tagy, běhy a joby v UI, ruční spuštění, recovery, maskování tokenů.
4. **Plánování** – APScheduler, detekce změn, override větví na projektu, retence, zrušení běhu.
5. **Dashboard** – DT klient pro čtení, verze a feature flags, cache, snapshoty, Přehled, Projekty, Detail, Zranitelnosti.
6. **Doladění** – Nastavení a testy připojení, `AUTH_MODE=proxy-header`, `CA_BUNDLE`, prázdné a chybové stavy, tmavý režim, testy, README.

---

## 18. Kontrolní seznam před odevzdáním

- [ ] uvicorn na `0.0.0.0:${PORT:-8000}`; obě build cesty (nixpacks, Docker) projdou a appka nastartuje
- [ ] `frontend/package-lock.json` v commitu, build nástroje v `dependencies`, `.nvmrc` = 22
- [ ] Trivy pinnutý s ověřeným checksumem, `trivy` a `git` dostupné (logováno při startu)
- [ ] bez GitLab/DT proměnných appka běží s bannerem; bez `DATABASE_URL` skončí s jasnou hláškou
- [ ] `/health` s `Cache-Control: no-store`
- [ ] žádné build-time proměnné; frontend bere runtime konfiguraci z `/api/status`
- [ ] trvalá data jen v PostgreSQL, migrace idempotentně při startu, dočasné soubory se uklízí
- [ ] tokeny nikde v logu, API ani frontendu
- [ ] subprocesy bez shellu, s timeoutem a zrušením; recovery po restartu
- [ ] identita jen přes `auth.py` podle `AUTH_MODE`
- [ ] žádný natvrdo psaný text pro uživatele; chyby jako kódy s parametry
- [ ] GitLab API volané jen z `services/sources/`
- [ ] v `SPEC.md`, README ani kódu nic specifického pro konkrétní firmu/prostředí (to patří do `SANDBOX.md`)

---

## 19. Ověřené prostředí (primární nasazení)

| Otázka | Odpověď | Dopad |
|---|---|---|
| Verze Dependency-Tracku | 4.14.4 | Využít `isLatest`, kolekční projekty, portfolio-wide nálezy; parametry ověřit v `/api/openapi.json`. |
| Dosažitelnost DT a GitLabu | Ano | Bez proxy a workaroundů. |
| Přístup na internet | Ano | Trivy se stahuje v buildu; `TRIVY_OFFLINE=false`. |
| Které větve skenovat | Volitelné, výchozí default branch | `branch_mode=default` jako výchozí, vlastní výběr na cíli i per projekt; dashboard jen z default branch. |
