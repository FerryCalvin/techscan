# Database Configuration

TechScan no longer ships with an embedded default Postgres password. All credentials must be supplied through environment
variables before the application starts.

## Required Variables

Set one of the following options:

1. Provide the full connection string via `TECHSCAN_DB_URL` (recommended for production).
2. Or provide individual components `TECHSCAN_DB_HOST`, `TECHSCAN_DB_PORT`, `TECHSCAN_DB_NAME`, `TECHSCAN_DB_USER`, and
   **mandatory** `TECHSCAN_DB_PASSWORD`.

If neither option is supplied the application aborts during start-up, preventing accidental use of hard-coded or personal
credentials.

## Local Development Override

For local experiments without a password you may opt into an explicit override:

```pwsh
$env:TECHSCAN_ALLOW_EMPTY_DB_PASSWORD = '1'
```

With the override enabled the password field is left empty and a warning is emitted in the logs. Never use this flag in
shared, staging, or production environments.

## Disabled Database Mode

Setting `TECHSCAN_DISABLE_DB=1` keeps all persistence in-memory for tests and CLI tooling. In this mode password variables
are ignored.
