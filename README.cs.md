<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="frontend/public/vulnyard-logo-dark.svg" />
    <img src="frontend/public/vulnyard-logo.svg" alt="Vulnyard" width="320" />
  </picture>
</p>

<p align="center">
  <strong>Centrální skenování zranitelností pro tvůj GitLab – bez pipeline, bez merge requestů.</strong><br />
  GitLab → Trivy → CycloneDX SBOM → Dependency-Track → jeden dashboard pro celou organizaci.
</p>

<p align="center">
  <a href="LICENSE"><img alt="Licence: Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" /></a>
  <img alt="Python 3.12+" src="https://img.shields.io/badge/python-3.12%2B-3776AB?logo=python&amp;logoColor=white" />
  <img alt="React 19" src="https://img.shields.io/badge/react-19-61DAFB?logo=react&amp;logoColor=black" />
  <img alt="Dependency-Track 4.12+" src="https://img.shields.io/badge/Dependency--Track-4.12%2B-4B5DA8" />
  <img alt="Trivy" src="https://img.shields.io/badge/scanner-Trivy-1904DA?logo=aqua&amp;logoColor=white" />
  <img alt="Docker" src="https://img.shields.io/badge/run%20with-Docker-2496ED?logo=docker&amp;logoColor=white" />
  <a href="#jak-vzniká"><img alt="Vzniká s pomocí AI" src="https://img.shields.io/badge/built%20with-AI%20assistance-8A2BE2" /></a>
</p>

<p align="center">
  <a href="https://vulnyard.eu">vulnyard.eu</a> ·
  <a href="#rychlý-start-docker">Rychlý start</a> ·
  <a href="CHANGELOG.md">Changelog</a> ·
  <a href="CONTRIBUTING.md">Přispívání</a> ·
  <a href="SECURITY.md">Bezpečnost</a> ·
  <a href="README.md">English</a> · <b>Česky</b>
</p>

---

**Vulnyard** ([vulnyard.eu](https://vulnyard.eu)) centrálně skenuje GitLab repozitáře
pomocí [Trivy](https://github.com/aquasecurity/trivy), generuje z nich SBOM
(CycloneDX), nahrává je do [Dependency-Tracku](https://dependencytrack.org) a nad
výsledky staví přehledný dashboard pro DevOps. Do skenovaných repozitářů se nic
nepřidává – žádné pipeline, žádné merge requesty.

**Obsah:** [Co umí](#co-aplikace-umí) · [Jak to funguje](#jak-to-funguje) ·
[Rychlý start](#rychlý-start-docker) · [Konfigurace](#konfigurace) ·
[Jak skenování funguje](#jak-skenování-funguje) · [Notifikace](#notifikace-do-chatu) ·
[Ignorování zranitelností](#ignorování-zranitelností) · [API a tokeny](#api-a-tokeny) ·
[Přihlášení a bezpečnost](#přihlášení-a-bezpečnost) · [Jazyky](#jazyky-a-překlady) ·
[Vývoj](#vývoj) · [Přispívání](#přispívání) · [Licence](#licence)

## Co aplikace umí

- **Cíle skenování** – GitLab skupina (volitelně včetně podskupin) nebo jednotlivý
  projekt. Nové repo ve skupině se najde samo. U každého cíle si vybereš větve
  (výchozí je default branch), plán (cron), výjimky a limit větví – a volitelně
  **vlastní instanci GitLabu a token**, když cíl žije jinde nebo nechceš jeden
  centrální token na všechno.
- **Skenování** – mělký klon, Trivy, CycloneDX SBOM, upload do Dependency-Tracku,
  tagy `vulnyard` a `source-group:<skupina>`. Projekt, jehož commit se od
  posledního skenu nezměnil, se přeskočí.
- **Dashboard** – souhrny podle závažnosti, trend (30/90/180 dní), nejrizikovější
  projekty, seznam projektů s filtry, detail projektu s nálezy a historií a
  přehled zranitelností napříč projekty („kde všude máme CVE-XXXX?“).
- **Notifikace do chatu** – po skenu, který najde zranitelnosti, pošle Vulnyard
  zprávu na webhook (Google Chat) s repozitářem, počty nálezů podle závažnosti a
  **maintainery repozitáře**. Webhook se nastavuje globálně, a u každého cíle jde
  přebít vlastním, když má chodit do jiného prostoru.
- **Ignorování zranitelností** – zranitelnost, kterou nebudete řešit, lze potlačit
  pravidlem pro jeden cíl, nebo pro celou aplikaci, volitelně jen pro vybrané
  komponenty (`pkg:npm/express@5.*`) a jen do zadaného data. Potlačení se posílá
  i do Dependency-Tracku.
- **Provoz** – historie běhů s chybami u jednotlivých jobů, ruční spuštění,
  zrušení běhu, plánovač, retence historie, testy připojení v Nastavení.
- **REST API s tokeny** – všechno z UI jde i přes API, takže jiný systém může
  třeba sám zakládat cíle skenování.
- **Vícejazyčné rozhraní** – čeština a angličtina; další jazyk přidáš jedním
  souborem s překladem.

## Jak to funguje

```mermaid
flowchart LR
    GL["GitLab<br/>skupiny a projekty"] -- "discovery, mělký klon" --> VY(["Vulnyard"])
    VY -- "Trivy → CycloneDX SBOM" --> DT[("Dependency-Track")]
    DT -- "nálezy a metriky" --> VY
    VY --> UI["Dashboard"]
    VY --> CH["Google Chat"]
    EXT["Jiné systémy"] -- "REST API + token" --> VY
```

## Rychlý start (Docker)

```bash
cp .env.example .env          # a doplň hodnoty, které máš
docker compose up --build     # aplikace + PostgreSQL
```

Aplikace běží na <http://localhost:8000>, health-check na `/health`.

Nemáš-li po ruce Dependency-Track, spusť si ho lokálně profilem `dtrack`:

```bash
docker compose --profile dtrack up --build
```

Dependency-Track API pak poslouchá na `http://localhost:8081`, jeho UI na
`http://localhost:8082`. V UI si vytvoř API klíč (výchozí přihlášení je
`admin`/`admin`, DT si hned vynutí změnu hesla) a do `.env` doplň
`DT_API_URL=http://dtrack-apiserver:8080`, `DT_UI_URL=http://localhost:8082` a
`DT_API_KEY=<klíč>`.

### Spuštění vydaného image

Každé vydání se publikuje jako kontejnerový image pro `linux/amd64` a
`linux/arm64` do `ghcr.io/oldsch00ler/vulnyard` (tagy `X.Y.Z`, `X.Y` a
`latest`). Server nepotřebuje checkout – stačí `docker-compose.yml` a `.env`:

```bash
VERSION=X.Y.Z                 # vydání, které chceš spustit
mkdir vulnyard && cd vulnyard
curl -fsSLO https://raw.githubusercontent.com/oldsch00ler/vulnyard/v$VERSION/docker-compose.yml
curl -fsSL -o .env https://raw.githubusercontent.com/oldsch00ler/vulnyard/v$VERSION/.env.example
# vyplň .env, nastav POSTGRES_PASSWORD a VULNYARD_IMAGE=ghcr.io/oldsch00ler/vulnyard:$VERSION
docker compose pull
docker compose up -d --no-build
```

Pro aktualizaci změň verzi ve `VULNYARD_IMAGE` a spusť poslední dva příkazy
znovu; migrace databáze proběhnou při startu. Přibalený PostgreSQL drží data ve
volume `postgres-data`. `AUTH_MODE=none` nikoho neověřuje, takže na dostupném
serveru dej aplikaci za VPN nebo autentizační proxy (viz
[Přihlášení a bezpečnost](#přihlášení-a-bezpečnost)).

## Konfigurace

Veškerá konfigurace jde přes proměnné prostředí – kompletní seznam s popisem je
v [`.env.example`](.env.example). Část nastavení se dá měnit v UI (stránka
Nastavení) a má pak přednost: souběh skenů, výchozí cron, retence historie,
globální výjimky a notifikace do chatu.

| Proměnná | Význam |
|---|---|
| `DATABASE_URL` | připojení do PostgreSQL (jediná povinná; `postgres://` i `postgresql://`) |
| `GITLAB_URL`, `GITLAB_TOKEN` | výchozí zdroj repozitářů (self-hosted i gitlab.com); cíl může mít vlastní |
| `DT_API_URL`, `DT_API_KEY`, `DT_UI_URL` | Dependency-Track (API, klíč, odkazy do UI) |
| `AUTH_MODE`, `AUTH_HEADERS` | `none` (výchozí) nebo `proxy-header` |
| `SCAN_CONCURRENCY`, `SCAN_TIMEOUT_SECONDS` | souběh skenů a timeout jednoho skenu |
| `TRIVY_BIN`, `TRIVY_OFFLINE` | cesta k Trivy a režim bez internetu |
| `CA_BUNDLE` | PEM s vlastní CA pro HTTP volání, git i Trivy |
| `TZ`, `DEFAULT_LOCALE`, `LOG_LEVEL` | časová zóna, výchozí jazyk (`cs`, `en`, …), úroveň logu |

Povinná je jen `DATABASE_URL`. Bez proměnných pro GitLab a Dependency-Track
aplikace normálně nastartuje, jen zobrazí banner s chybějící konfigurací a
skenování je vypnuté.

### Vlastní GitLab a token u cíle

`GITLAB_URL` a `GITLAB_TOKEN` jsou výchozí hodnoty. Každý cíl je může přebít:

- **jen token** – stejná instance, ale token omezený třeba na jednu skupinu,
- **URL i token** – cíl na úplně jiné instanci GitLabu (token je pak povinný).

Jeden běh tak může sahat na několik instancí naráz a klon každého projektu
používá token svého cíle. Pokud mají vlastní údaje všechny cíle, `GITLAB_TOKEN`
v prostředí není potřeba vůbec. Token se ukládá do databáze, **do API ani do
prohlížeče se nikdy nevrací** (jen příznak „nastaveno“) a v logu se maskuje.
V úpravě cíle je tlačítko „Otestovat připojení“, které ověří instanci i token
ještě před uložením.

### Potřebná oprávnění tokenů

- **GitLab:** group access token na nejvýš skenované skupině, role **Reporter**,
  scope `read_api` + `read_repository`. Osobní token není potřeba. Token se
  používá i pro klon přes HTTPS.
- **Dependency-Track:** API klíč týmu s oprávněními `BOM_UPLOAD`,
  `PROJECT_CREATION_UPLOAD`, `VIEW_PORTFOLIO`, `VIEW_VULNERABILITY` a
  `PORTFOLIO_MANAGEMENT` (poslední je potřeba na doplňování tagů). Tlačítko
  **Otestovat připojení** v Nastavení ověří dostupnost a verzi Dependency-Tracku,
  oprávnění klíče ale nezkouší – chybějící oprávnění se projeví až při skenu,
  chybou se seznamem toho, co klíč potřebuje.

### Podporované verze Dependency-Tracku

Minimální podporovaná verze je **4.12**, ověřeno na **4.13** a **4.14**. Pod 4.12
se skenování nezapne a Nastavení to vysvětlí.

Verze Trivy je připnutá ve [`scripts/install-trivy.sh`](scripts/install-trivy.sh)
a je svázaná s verzí Dependency-Tracku formátem CycloneDX:

| Trivy | CycloneDX | Přijímá |
|---|---|---|
| 0.70.0 (výchozí) | 1.6 | Dependency-Track 4.12 a novější |
| 0.71.0+ | 1.7 | Dependency-Track 4.14 a novější |

Proto je výchozí 0.70.0. Pokud všechny tvé instance běží na 4.14+, můžeš Trivy
povýšit – při špatné kombinaci sken selže s hláškou, která to přesně říká.

## Jak skenování funguje

Aplikace si u každého cíle sama zjistí projekty a větve. Každý projekt a větev je
jeden job ve frontě: mělký klon (`--depth 1 --single-branch`), Trivy vygeneruje
CycloneDX SBOM, ten se nahraje do Dependency-Tracku (`autoCreate`, default branch
se označí jako `isLatest`) a aplikace počká, než ho DT zpracuje. Projekt v DT se
jmenuje podle cesty repozitáře, verze je název větve. Skupinový cíl navíc dostane
nadřazený kolekční projekt, který agreguje metriky svých potomků.

Analýzu zranitelností dělá Dependency-Track, ne Trivy – nová CVE se tak objeví i
bez nového skenu. Klony se po skenu vždy mažou, do repozitářů se nikdy nic
nezapisuje a souhrny na Přehledu se počítají jen z default branch, aby se
zranitelnosti z více větví téhož repa nesčítaly.

## Notifikace do chatu

V **Nastavení** zapneš notifikace, vložíš webhook Google Chatu a vybereš minimální
závažnost (výchozí „vysoké“). Zpráva se pošle po každém skenu, u kterého
Dependency-Track hlásí nález alespoň téhle závažnosti, a obsahuje:

```
*Vulnyard: zranitelnosti v `team/app`* (větev `main`)
kritické: 2 · vysoké: 5 · střední: 3
Cíl skenování: Team
Maintaineři repa: Jan Novák (@jnovak, Owner), Eva Malá (@emala, Maintainer)
Repozitář · Dependency-Track
```

Zprávy jsou v jazyce `DEFAULT_LOCALE`.

**Kdo se ve zprávě objeví:** přednost mají lidé **přidaní přímo k repozitáři** –
z nich Owner a Maintainer, a pokud takový nikdo není, Developeři. Zdědění členové
ze skupiny se použijí jen tehdy, když projekt nemá vlastní členy vůbec, a zpráva
to pak řekne („Repo nemá vlastní členy, maintaineři skupiny…“), protože zděděný
člen typicky není autor repa. Uživatelé pro přístupové tokeny se vynechávají.
GitLab e-maily členů nevydává, takže zpráva uvádí jméno, `@username`, roli a
odkaz na profil – zmínka (`@`) v Google Chatu proto nikoho reálně nenotifikuje.

**Vlákna:** všechna oznámení o jednom repozitáři (napříč větvemi) chodí do jednoho
vlákna, ne do nové konverzace. Aplikace posílá `thread.threadKey` odvozený z cesty
repa spolu s `messageReplyOption=REPLY_MESSAGE_FALLBACK_TO_NEW_THREAD`: první
zpráva vlákno založí, další se do něj přidávají. Předpokládá to prostor s vlákny
(„Grouped by conversation topic“); v plochém prostoru Google Chat klíč ignoruje a
zprávy jdou za sebou.

**Vlastní webhook u cíle:** v úpravě cíle je pole „Vlastní webhook do chatu“. Když
ho vyplníš, notifikace tohoto cíle jdou tam místo globálního webhooku – a posílají
se i tehdy, když je globální přepínač vypnutý. Webhook obsahuje klíč a token, takže
se do prohlížeče ani do logu nikdy nevrací celý, jen zkrácený. Tlačítkem lze poslat
testovací zprávu.

Zpráva vedle stavu říká i **co je nového od posledního skenu** („Od posledního
skenu: kritické +3“), takže se z ní dá poznat zhoršení, ne jen opakovaný stav.

**Zlepšení chodí taky.** Když repozitář nálezy nad nastavenou hranicí měl a po
opravě už je nemá, přijde do stejného vlákna zpráva „je zase čisté“ s rozdílem a
s tím, co případně zbývá pod hranicí – jinak by se spravené repo jen odmlčelo a
to vypadá stejně jako by ho nikdo neskenoval. Repozitář, který byl čistý už
předtím, žádnou zprávu negeneruje.

**Když se rozbije samo skenování** (vyprší GitLab token, Dependency-Track odmítne
klíč, zmizí Trivy), přijde zpráva „skenování se nedaří“ s důvodem a číslem běhu –
jinak by ticho vypadalo stejně jako „nic jsme nenašli“. Hlásí se to jen u chyb,
které postihnou celý běh, ne u jednoho podivného repa, a stejný problém nejvýš
raz za šest hodin.

Selhání chatu nikdy neshodí sken – zaloguje se varování a běh pokračuje.

## Ignorování zranitelností

Ne každý nález se dá nebo musí opravit. Zranitelnost jde označit jako ignorovanou
v **Zranitelnostech** (tlačítko „Ignorovat“ u řádku) nebo v **Nastavení**, kde je
i seznam všech pravidel.

Pravidlo má:

- **rozsah** – jeden cíl skenování, nebo celá aplikace,
- **vzor komponenty** – glob nad purl. `*` znamená „tuhle zranitelnost kdekoliv
  v rozsahu“, `pkg:npm/express@5.*` jen express verze 5. Ve formuláři se našeptávají
  purl komponent, které zranitelnost skutečně mají,
- **stav analýzy pro Dependency-Track** – „netýká se nás“, „falešný nález“,
  „vyřešeno“,
- **důvod** – zapíše se do komentáře analýzy v DT, aby to bylo dohledatelné i tam,
- **platnost do** – nepovinná. Po tom dni pravidlo přestane platit a potlačení se
  zruší. Užitečné pro „teď to neřešíme, ale ať se to za měsíc vrátí“.

Potlačení se **vždy posílá do Dependency-Tracku** (`PUT /api/v1/analysis`), i když
pravidlo platí jen pro jeden cíl. Přehled, graf trendu i notifikace do chatu čtou
počty z metrik DT, takže nález skrytý jen ve Vulnyardu by se tam dál počítal a
čísla by si přestala odpovídat.

Pravidla se aplikují při uložení, po každém skenu (nový sken přináší nové verze
komponent) a jednou denně, aby se projevila expirace. Operace je idempotentní a
funguje oběma směry – co pravidlo přestalo pokrývat, se odpotlačí. Když je
Dependency-Track nedostupný, pravidlo se uloží i tak a další běh ho dopošle;
ručně to jde vynutit tlačítkem „Aplikovat pravidla znovu“.

## API a tokeny

Všechno, co umí UI, jde i přes REST API pod `/api` – interaktivní dokumentace
(Swagger UI) je na **`/api/docs`**, schéma na `/api/openapi.json`. Jiný systém
se k API přihlašuje **API tokenem**:

1. V **Nastavení → API tokeny** vytvoř token: název (kdo ho bude používat),
   oprávnění **jen čtení** nebo **čtení i zápis** a volitelně datum platnosti.
2. Token se zobrazí **jen jednou** – hned si ho ulož do systému, který ho bude
   používat. Aplikace si drží jen jeho otisk (SHA-256), takže ho zpětně
   ukázat nejde; ztracený token smaž a vytvoř nový.
3. Posílej ho v hlavičce `Authorization: Bearer vy_…`.

Příklad – automat, který při vzniku nového projektu v GitLabu založí cíl
skenování (token s oprávněním k zápisu):

```bash
curl -X POST https://vulnyard.example.com/api/targets \
  -H "Authorization: Bearer $VULNYARD_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"kind": "project", "source_ref": "1234"}'
```

`source_ref` je ID projektu (nebo skupiny při `"kind": "group"`) v GitLabu;
název a cestu si aplikace doplní sama. Ostatní pole (větve, cron, výjimky…)
jsou nepovinná a mají stejné výchozí hodnoty jako formulář – viz `/api/docs`.
Duplicitní cíl vrátí `409`, takže opakované volání nic nerozbije.

Pravidla:

- změny udělané tokenem se v auditu (`updated_by`, `triggered_by`, `created_by`)
  zapíší jako `token:<název>`,
- token „jen čtení“ smí jen `GET`, ostatní dostane `403`,
- neplatný, smazaný nebo prošlý token dostane `401`,
- tokeny může vytvářet a mazat jen člověk v UI, nikdy jiný token,
- tokeny se nikdy neobjeví v logu ani v odpovědích API (kromě té jedné při
  vytvoření); v seznamu je jen prvních pár znaků, aby šly rozlišit.

Jak se tokeny chovají v režimech přihlášení, popisuje následující sekce.

## Přihlášení a bezpečnost

- **`AUTH_MODE=none`** (výchozí): aplikace nikoho nepřihlašuje – přístup má
  kdokoli, kdo se k ní dostane po síti. **Provozuj ji za VPN nebo za
  autentizující reverzní proxy.** UI i log to říkají při každém startu.
- **`AUTH_MODE=proxy-header`**: identitu nastavuje autentizující reverzní proxy
  (oauth2-proxy, Authelia, Traefik forward-auth, firemní SSO). Backend čte e-mail
  z hlaviček v `AUTH_HEADERS` (v tomto pořadí) a ukládá ho k auditu ke změnám
  cílů a k ručně spuštěným běhům. V tomto režimu **nesmí být aplikace dosažitelná
  mimo proxy** – jinak si hlavičku může podvrhnout kdokoli.
- **API tokeny** fungují v obou režimech. V `none` jsou nepovinné – API je
  dál otevřené jako dřív (UI tokeny nepoužívá) a token jen říká, kdo změnu
  udělal; před cizími chrání API pořád síť. V `proxy-header` stačí platný
  token místo hlavičky s identitou – proxy ale musí requesty s
  `Authorization: Bearer vy_…` pustit k aplikaci, a pokud je pouští bez
  přihlášení, musí od klienta zahazovat hlavičky z `AUTH_HEADERS`. Hlavičku
  `Authorization` s jiným než naším tokenem (třeba JWT, které proxy posílá
  dál) aplikace ignoruje.

Tokeny zůstávají na serveru: frontend nevolá GitLab ani Dependency-Track přímo a
tokeny se nikdy neobjeví v API odpovědích ani v logu (výstupy podprocesů i chyby
HTTP volání se maskují). Podprocesy se spouštějí bez shellu, s timeoutem a
zrušením; názvy větví se validují. Stránka Nastavení ukazuje u proměnných jen
to, jestli jsou nastavené – nikdy jejich hodnoty.

## Vývoj

Předpoklady: Python 3.12+, Node 22 (viz `frontend/.nvmrc`), git, Trivy a
PostgreSQL. PostgreSQL z `docker-compose.yml` port ven nepublikuje, pro vývoj si
pusť vlastní:

```bash
docker run -d --name vulnyard-db -p 5432:5432 \
  -e POSTGRES_USER=vulnyard -e POSTGRES_PASSWORD=vulnyard -e POSTGRES_DB=vulnyard \
  postgres:17-alpine
```

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
bash scripts/install-trivy.sh ./.bin          # Trivy s ověřeným checksumem

cd frontend && npm ci && npm run build && cd ..
export DATABASE_URL=postgresql://vulnyard:vulnyard@localhost:5432/vulnyard
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Frontend v dev režimu (proxy na backend na portu 8000): `cd frontend && npm run dev`.

**Databáze:** migrace se spouští samy při startu aplikace (`alembic upgrade head`).
Novou migraci vytvoříš po změně modelů takto:

```bash
export DATABASE_URL=postgresql://vulnyard:vulnyard@localhost:5432/vulnyard
alembic revision --autogenerate -m "popis změny"
alembic check                 # ověří, že modely a migrace souhlasí
```

**Testy:** `pytest`. Testy, které potřebují skutečný PostgreSQL (API nad
databází), se přeskočí, dokud nenastavíš databázi, do které smí zapisovat
(testy ji před každým testem vyprázdní, takže vlastní, ne tu vývojovou):

```bash
docker exec vulnyard-db createdb -U vulnyard vulnyard_test
export VULNYARD_TEST_DATABASE_URL=postgresql://vulnyard:vulnyard@localhost:5432/vulnyard_test
pytest
```

Aplikace běží v jedné instanci – plánovač i worker jsou součástí webového
procesu, horizontální škálování není cílem v1.

### Dvě build cesty

V repozitáři jsou obě a obě musí zůstat funkční:

- **Docker** – `Dockerfile`, `docker-compose.yml` (výchozí cesta),
- **nixpacks** – `nixpacks.toml` a `requirements.txt` v kořeni (platformy typu
  Coolify nebo Railway).

Trivy instaluje v obou cestách `scripts/install-trivy.sh`: verze je ve skriptu
pevně zapsaná a stažený archiv se ověřuje proti SHA256 checksumu.

### Publikování na GitHub (pro správce)

Vývoj probíhá upstream, GitHub dostává snapshoty. `scripts/publish-github.sh`
vytvoří ve větvi `github` commit z `main` bez cest z
`.publishignore` a s vlastní historií, takže se ven nikdy
nedostane nic z historie upstreamu. Před vytvořením commitu výsledek prohledá
(domény zmíněné ve vyloučených souborech, privátní klíče, soubory `.env`) a
nainstaluje pre-push hook, který na remote s github.com pustí jen větev `github`.

```bash
scripts/publish-github.sh               # nebo: -m "Verze 1.2" jako titulek commitu
git push github github:main
```

### Vydání a changelog (pro správce)

Verze se řídí [sémantickým verzováním](https://semver.org/lang/cs/); vydání je
tag `vX.Y.Z`. [`CHANGELOG.md`](CHANGELOG.md) generuje z commitů od posledního
vydání `scripts/release.py`, který zároveň zvedne verzi (backend i frontend),
commitne a otaguje. Nic nepushuje.

```bash
scripts/release.py --dry-run            # náhled další verze a jejího changelogu
scripts/release.py                      # nebo: scripts/release.py 1.0.0
git push origin main vX.Y.Z
scripts/publish-github.sh               # snapshot + tag github/vX.Y.Z pro GitHub
git push github github:main refs/tags/github/vX.Y.Z:refs/tags/vX.Y.Z
scripts/release.py notes vX.Y.Z         # text pro GitHub Release
```

Push tagu `vX.Y.Z` na GitHub spustí workflow *Container image*
(`.github/workflows/image.yml`), který sestaví image a publikuje ho do
`ghcr.io/oldsch00ler/vulnyard`. Po úplně prvním publikování jednou přepni balíček
na veřejný v jeho nastavení na GitHubu (Packages → vulnyard → Package settings →
Change visibility).

Kam commit v changelogu patří, určí trailer `Changelog:` (`added`, `fixed`,
`changed`, `removed`, `security`, `breaking`, `skip`…), prefix Conventional
Commits (`feat:`, `fix:`, `feat!:`; `chore:`, `docs:`, `test:`… se vynechají),
nebo první slovo předmětu („Add …“, „Fix …“, „Remove …“; ostatní je Changed).
Viz [CONTRIBUTING.md](CONTRIBUTING.md#commit-messages).

## Jazyky a překlady

Rozhraní, chybové hlášky API, log i zprávy do chatu jsou ve všech jazycích, pro
které existuje katalog. Teď je to **čeština** a **angličtina**.

- **Rozhraní** si jazyk vybírá přepínačem v hlavičce (zobrazí se, jakmile jsou
  aspoň dva jazyky) a pamatuje si ho v prohlížeči. Bez výběru platí
  `DEFAULT_LOCALE`.
- **Chyby z API** jsou v jazyce z hlavičky `Accept-Language`. Rozhraní posílá
  ten, který máš zvolený, jiné systémy si o jazyk řeknou stejně.
- **Log a zprávy do chatu** jsou vždy v jazyce `DEFAULT_LOCALE`, protože je čte
  víc lidí najednou.

### Jak přidat jazyk

Přidání jazyka jsou **dva soubory, žádný kód**. Jako vzor vezmi angličtinu
(referenční katalog, vždy kompletní):

1. `frontend/src/i18n/locales/<jazyk>.json` – texty rozhraní. Zkopíruj `en.json`
   a přelož hodnoty. `language.name` je název jazyka v něm samém („Deutsch“) –
   ten se ukáže v přepínači.
2. `app/i18n/<jazyk>.json` – hlášky backendu (chyby API, log, chat). Zkopíruj
   `en.json` a přelož hodnoty.

`<jazyk>` je kód podle BCP 47: `de`, `fr`, `pt-BR`… Aplikace oba soubory najde
sama, po sestavení frontendu se jazyk objeví v přepínači a dá se nastavit i
jako `DEFAULT_LOCALE`.

Pravidla pro překladatele:

- překládej jen hodnoty, klíče nech beze změny,
- placeholdery nech, jak jsou: ve frontendu `{{count}}`, v backendu `{count}`,
- množná čísla: ve frontendu má klíč tvary podle pravidel jazyka (`_one`,
  `_few`, `_many`, `_other`… – viz
  [CLDR](https://www.unicode.org/cldr/charts/latest/supplemental/language_plural_rules.html)).
  Angličtina má jen `_one` a `_other`, čeština i `_few` a `_many`,
- katalog nemusí být hned kompletní – chybějící texty se ukážou anglicky.

`pytest` (`tests/test_i18n.py`) zkontroluje každý katalog: že nemá neznámé klíče
(překlep), že žádná hláška nepřišla o placeholder nebo nepřidala cizí a že
dodávané katalogy (`cs`, `en`) jsou kompletní.

## Jak vzniká

Vulnyard vzniká za pomoci AI nástrojů pro programování, převážně Claude. Návrh,
rozhodnutí a kontrola každé změny jsou na mně: vygenerovaný kód prochází stejnými
testy, review a procesem vydání jako jakýkoli jiný a za to, co se vydá, odpovídám
já.

## Přispívání

Hlášení chyb, nápady, překlady i pull requesty jsou vítané – viz
[CONTRIBUTING.md](CONTRIBUTING.md) (anglicky). Našel jsi bezpečnostní chybu?
Nahlas ji prosím soukromě podle [SECURITY.md](SECURITY.md), ne ve veřejném issue.

## Licence

Apache-2.0, viz [`LICENSE`](LICENSE) a [`NOTICE`](NOTICE).
Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>.
