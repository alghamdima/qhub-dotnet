# Qhub (reimagined)

One ASP.NET Core 10 modular monolith on SQL Server (EF Core). The design is in `analysis/qhub/REIMAGINED_ARCHITECTURE.md`, and the behaviour it must meet is in `analysis/qhub/AI_NATIVE_SPEC.md` §5.

## Build and test

```sh
dotnet restore
dotnet build -warnaserror
dotnet test            # Microsoft.Testing.Platform (see global.json)
```

- **Docker:** the tests need Docker. One `mcr.microsoft.com/mssql/server:2022-latest` container starts per test run, and each test gets its own database in it. Without Docker, the SQL Server tests fail with a clear message, and the other tests still run. To use an existing SQL Server instead, set `QHUB_TEST_SQL` to a connection string with rights to create databases.
- **Pending rules:** each Behavior Contract rule has one test in `tests/Qhub.Tests/Acceptance/Phase1|2|3/`, named after its rule ID and tagged `[TestCategory("RULE-xxx")]`. A rule that isn't implemented yet reports as skipped, with the message `pending: RULE-xxx` (plus `, awaiting Q1` for corrected rules whose Q1 box in the brief isn't ticked).
- **Run one rule:** `dotnet test --filter "TestCategory=RULE-128"`.

## End-to-end scenario

`e2e/` drives a running instance (for example the Docker one) in real Chrome through every persona flow: see `e2e/SCENARIO.md`. Run `cd e2e && npm install && node scenario.js`.

## Migrations

`dotnet ef` comes from the local tool manifest (`dotnet-tools.json`):

```sh
dotnet tool restore
dotnet ef migrations add <Name> --project src/Qhub --output-dir Data/Migrations
```

The app applies its migrations at startup, so its database login needs DDL rights. It refuses to start when the database holds migrations this build doesn't know (RULE-037).

## Configuration

Settings come only from `QHUB_*` environment variables, and none of the secrets has a default. The app checks every setting at startup and stops with the full list of errors (RULE-038).

- **Secrets:** pass them as Docker secrets through the `_FILE` form, for example `QHUB_DB_CONNECTION_FILE=/run/secrets/qhub_db`. Setting both `QHUB_X` and `QHUB_X_FILE` is an error. The secrets are:
  - `QHUB_DB_CONNECTION` (a SQL Server connection string)
  - `QHUB_SERVER_KEY` (32 random bytes, base64-encoded)
  - `QHUB_ADMIN_PASSWORD`
  - `QHUB_ENCRYPTION_PASSWORD`
  - `QHUB_AWS_KEY_SECRET`
- **Required:**
  - `QHUB_PUBLIC_URL` (`https://`; `http://` is allowed only for localhost)
  - `QHUB_DB_CONNECTION`
  - `QHUB_SERVER_KEY`
  - `QHUB_DATA_PROTECTION_CERT_FILE` (one PEM file with the certificate and its private key)
  - `QHUB_ADMIN_PASSWORD`, when `QHUB_AUTH` includes `internal`
- **Other names:**
  - Server: `QHUB_PORT`, `QHUB_PUBLIC_NAME`, `QHUB_REDIRECT_URL`, `QHUB_TRUSTED_PROXIES`
  - Sign-in: `QHUB_AUTH`, `QHUB_ADMIN_USER`, `QHUB_SAML_IDP_METADATA`, `QHUB_MIN_LENGTH_PASSWORD`
  - Admin UI: `QHUB_DISABLE_API_MENU`
  - Uploads: `QHUB_CHUNK_SIZE_MB`, `QHUB_MAX_FILESIZE`, `QHUB_MAX_MEMORY_UPLOAD`, `QHUB_MAX_PARALLEL_UPLOADS`, `QHUB_MIN_FREE_SPACE`, `QHUB_LENGTH_ID`
  - Logging: `QHUB_LOG_STDOUT`, `QHUB_LOG_RETENTION_DAYS`, `QHUB_SAVE_IP`
  - Storage: `QHUB_ENCRYPTION` (`none` or `on`), `QHUB_DATA_DIR`
  - S3: `QHUB_AWS_BUCKET`, `QHUB_AWS_REGION`, `QHUB_AWS_KEY`, `QHUB_AWS_ENDPOINT`, `QHUB_AWS_PROXY_DOWNLOAD`

## Run with Docker

```sh
bash deploy/make-secrets.sh     # creates .env and deploy/secrets/* (gitignored), never overwrites
docker compose up -d --build    # SQL Server + Qhub on http://localhost:8080
```

If port 8080 is taken, set `QHUB_HOST_PORT=8090` (or another port) in `.env`. Sign in at `/login` as `admin` with the password in `deploy/secrets/admin_password`. For a real host, set `QHUB_PUBLIC_URL` to its `https://` address in `.env` and put a TLS proxy in front (add its address to `QHUB_TRUSTED_PROXIES`).

### Changing settings

- **Where settings live:** every setting is a `QHUB_*` variable in `.env`; `.env.example` lists them all with defaults. Secrets go in `deploy/secrets/` and reach the app as Docker secrets (`QHUB_*_FILE`). The image holds no secrets or settings except `QHUB_PORT=8080` and `QHUB_DATA_DIR=/data`.
- **Settings in `.env`:** after an edit run `docker compose up -d`, which recreates the container. `docker compose restart` does **not** reread `.env`.
- **Secret files and `custom/`:** `docker compose restart` is enough.
- **Rebuilds:** only code changes need `docker compose build`.
- **Bad values:** the app refuses to start and lists every problem in `docker compose logs qhub`.

## Deferred

- SAML sign-in (RULE-066): deferred at the user's request; `QHUB_AUTH=saml` is refused at startup. Needs `ITfoxtec.Identity.Saml2`.
- The S3 store is written but untested against an S3 mock (MinIO): deferred at the user's request.
- The QR logo overlay and per-size favicons (`SkiaSharp`): the QR is plain and every favicon size serves the same PNG.
