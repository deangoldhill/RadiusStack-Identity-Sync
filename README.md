# RadiusStack Identity Sync — staging source

This bundle contains only the Go application source and deployment inputs. It does **not** contain the live database, administrator password, API keys, firewall shared secrets, logs, backups, or test files.

## Deploy on staging

1. Copy `.env.example` to `.env` and set a long, unique `DEFAULT_ADMIN_PASSWORD`. Keep `.env` private (`chmod 600 .env`). These values create the **first** administrator only; later edits do not reset an existing account.
2. Ensure the external Docker network `radiusstack_radius_net` exists on staging and connects to the intended RadiusStack API/RADIUS services. If staging uses another network, edit the Compose network name and relevant API/RADIUS configuration deliberately before deployment.
3. Check that TCP port 8111 is available (or change the published port in `compose.yaml`). Run `docker compose config --quiet`, then `docker compose up -d --build`.
4. The one-shot `data-init` service must exit 0 before the non-root app starts. Verify `docker compose ps --all`, `docker logs identity-sync`, and `http://<staging-host>:8111/healthz`. Log in with the new bootstrap account and check the dashboard.

Persistent configuration lives in the `identity-sync-data` named volume. `docker compose down -v` **deletes** that volume and its application database; ordinary `docker compose down` does not.

JSON configuration exports include secrets and password hashes. Transfer and store them as sensitive files; they are not part of this source bundle.
