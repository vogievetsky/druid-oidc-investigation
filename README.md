# Druid web console + OIDC (`druid-pac4j`) investigation

How does Apache Druid's OIDC login (the [`druid-pac4j`](https://druid.apache.org/docs/latest/development/extensions-core/druid-pac4j)
extension) actually work with the web console? This repo has a reproducible local setup (Druid + Keycloak with mock users),
the scripts used to probe it, the evidence, and a list of suggested ToDos for the **web console** and the **docs**
(plus some for the extension itself).

The docs currently say:

> The pac4j authenticator should only be used at the router node to enable a group of users in existing authentication
> server to interact with Druid cluster, using the web console.

That raised two questions, which this investigation answers:

1. **The web console has no token-refresh code. How does it keep working?** It doesn't need tokens, and when the session
   ends it simply breaks until the user reloads the page.
2. **What is special about the router? Isn't it just a proxy?** Nothing in the code. It is just the place the browser
   talks to, and it does *not* forward the user's identity to anyone.

Tested on 2026-10-19 with Druid `master` @ `3e9c628f08` (40.0.0-SNAPSHOT), pac4j 5.8.0, Keycloak 26.0.7, and Chromium
driven by Playwright 1.48.2.

## TL;DR

- **The session is one encrypted cookie** (`pac4j.session.pac4jUserProfiles`) holding the user's pac4j profile, encrypted
  with `druid.auth.pac4j.cookiePassphrase`. The console never sees a token. No server keeps session state.
- **Session lifetime = min(IdP token lifetime, 15 minutes)**, counted from login. The 15 minutes is hard-coded
  (`Max-Age=900`). Activity doesn't extend it.
- **After that, every console request breaks with "Network Error".** The API call gets a 302/303 redirect to the IdP, the
  browser blocks it (CORS), and axios reports a network error. Only a **full page reload** recovers. The reload goes
  through the IdP, which still remembers the user, so they come back without typing a password.
- **One-line fix direction for the console:** send `X-Requested-With: XMLHttpRequest`. pac4j then answers expired or
  missing sessions with a clean **`401` + `WWW-Authenticate: Bearer realm="pac4j"`** that the console can detect and
  turn into a "session expired, sign in again" experience. Verified in a real browser.
- **"Router only" (docs taken literally) leaves the broker, coordinator, etc. completely unauthenticated**, and the broker
  sees every console user as the same anonymous user. Per-user permissions are impossible in that setup.
- **pac4j on every service works.** The router forwards the browser's cookie, and the broker or coordinator decrypts it
  with the shared passphrase and gets the real user. Internal traffic needs `basic` (or similar) in front of `pac4j` in
  the authenticator chain.
- **Of the six documented `clientAuthenticationMethod` values, only `client_secret_basic` and `client_secret_post`
  work**, and the default (auto-detect) broke for Keycloak in the pac4j 5 upgrade. That setting only affects the
  router↔IdP back channel. The browser session is the same cookie either way.
- Several doc gaps (callback URL, `authorizerName`, `oidcClaim`, session lifetime, HTTPS) and a few extension issues
  (lost profile context, ~40 ms per request, no logout). See [ToDos](#todos).

## How it works

```mermaid
sequenceDiagram
    autonumber
    participant B as Browser (web console)
    participant R as Router :8888 (pac4j)
    participant K as Keycloak (IdP)
    participant BR as Broker / Coordinator

    B->>R: GET /unified-console.html (no session cookie)
    R-->>B: 302 to IdP authorize endpoint<br/>+ cookies: state, nonce, PKCE verifier, requested URL (encrypted)
    B->>K: login form (alice / alice)
    K-->>B: 302 /druid-ext/druid-pac4j/callback?code=...
    B->>R: GET callback?code=...
    R->>K: exchange code for tokens (client_secret_basic)
    R-->>B: 302 /unified-console.html<br/>+ Set-Cookie pac4j.session.pac4jUserProfiles (encrypted profile, Max-Age=900)
    B->>R: XHR /druid/v2/sql (cookie attached by the browser)
    R->>BR: proxied as-is (same headers/cookies, NO identity added)
    Note over BR: router-only config: no auth here, request runs as anonymous "allowAll"<br/>all-services config: pac4j decrypts the forwarded cookie, identity = alice's sub
    BR-->>B: 200
    Note over B,R: ...token expires (IdP lifetime) or 15 minutes pass...
    B->>R: XHR /druid/v2/sql
    R-->>B: 303 to IdP authorize endpoint
    B-xK: cross-origin redirect blocked by CORS -> axios "Network Error"
```

Relevant code:

- [`Pac4jFilter`](https://github.com/apache/druid/blob/master/extensions-core/druid-pac4j/src/main/java/org/apache/druid/security/pac4j/Pac4jFilter.java):
  handles the callback path and runs pac4j's `DefaultSecurityLogic` on every other request.
- [`Pac4jSessionStore`](https://github.com/apache/druid/blob/master/extensions-core/druid-pac4j/src/main/java/org/apache/druid/security/pac4j/Pac4jSessionStore.java):
  stores every pac4j session value as its own encrypted cookie (`Max-Age=900`, always `Secure`, `HttpOnly`). Adapted
  from Apache Knox.
- [`Pac4jAuthenticator`](https://github.com/apache/druid/blob/master/extensions-core/druid-pac4j/src/main/java/org/apache/druid/security/pac4j/Pac4jAuthenticator.java):
  `setExpireSessionWithToken(true)`, `setUseNonce(true)`. It does **not** override `Authenticator.decorateProxyRequest`;
  only Kerberos does.
- [`AsyncQueryForwardingServlet`](https://github.com/apache/druid/blob/master/services/src/main/java/org/apache/druid/server/AsyncQueryForwardingServlet.java):
  the router's proxy. It uses a plain (non-escalated) Jetty client and only calls `decorateProxyRequest`, so for pac4j
  the downstream service gets exactly the browser's headers and cookies.

## Findings

### 1. The console has no session handling, so expiry shows up as "Network Error"

Real Chromium, logged in as `alice`, idle for 150 s (realm token lifetime is 120 s), then the console's normal requests
([full log](evidence/browser-expiry-run.log)):

```
fresh session: XHR (what the console does)   -> status 200
after expiry:  XHR (what the console does)   -> onerror (status 0) -> axios would report "Network Error"
after expiry:  XHR + X-Requested-With header -> status 401 www-authenticate=Bearer realm="pac4j" body=<html>...
browser console: Access to XMLHttpRequest at 'http://localhost:18080/realms/druid/protocol/openid-connect/auth?scope=openid+profile+email&response_type=code&redirect_uri=http%3A%2F%2Flocalhost%3A8888%2Fdruid-ext%2Fdru...
request failed:  GET http://localhost:18080/realms/druid/protocol/openid-connect/auth?... net::ERR_FAILED
full page reload -> login form shown? false   (silently re-authenticated through the IdP's own session)
after reload:  XHR (what the console does)   -> status 200
```

What the user sees after expiry (the Services view), with nothing telling them to reload:

![Services view showing "Network Error"](evidence/2-after-expiry-services.png)

Notes:

- pac4j decides "is this AJAX?" with its default `AjaxRequestResolver`, i.e. the `X-Requested-With: XMLHttpRequest`
  header. axios doesn't send it, so the console gets the browser-style redirect.
- Verified with curl that with the header, **both GET and POST** get `401` + `WWW-Authenticate: Bearer realm="pac4j"`,
  and that the header doesn't affect `basic` auth (`curl -u admin:admin -H 'X-Requested-With: XMLHttpRequest'` → 200).
- Every console request goes through the single axios instance created in
  [`web-console/src/entry.tsx`](https://github.com/apache/druid/blob/master/web-console/src/entry.tsx) (no raw
  `fetch`/`EventSource`), so one header covers everything.
- **Workaround that exists today, no code change:** `customHeaders` in `console-config.js` can add
  `{"X-Requested-With": "XMLHttpRequest"}`. But the 401 body is Jetty's HTML error page, and the console's axios
  interceptor uses a string response body as the error message for GETs, so users would see raw HTML instead of
  "Network Error". Better, still not good.
- What survives a reload: workbench tabs (query text) are in `localStorage`. Results, running-query tracking and open
  dialogs are lost.

### 2. Session lifetime: min(IdP token lifetime, 15 minutes), not sliding

- `pac4j.session.pac4jUserProfiles` is set once, at the callback, with `Max-Age=900`. Authenticated requests do **not**
  re-issue it (checked: each request only re-sets the CSRF cookies: three encrypted `pac4j.session.*Csrf*` ones plus a
  plain `pac4jCsrfToken`).
- `setExpireSessionWithToken(true)` is enforced. Login at 23:27:16Z with a 120 s token lifetime: a request at 23:29:42Z
  with the same cookie got `302` to the IdP.
- So with Keycloak's default 5-minute token lifetime, console users get kicked out every 5 minutes. With a 1-hour token
  lifetime (common for Okta etc.), it's every 15 minutes.
- Because the IdP keeps its own longer session (Keycloak `KEYCLOAK_IDENTITY` cookie), a top-level navigation to Druid
  re-authenticates without a password prompt. That is why "just reload" works and why the console can get away with
  having no refresh-token logic.

### 3. "Only at the router": what it actually means

Two configs were tested (see [`druid/`](druid)):

| | `oidc-router-only` (docs taken literally) | `oidc-all` (`["basic", "pac4j"]` on every service) |
|---|---|---|
| Console via router | works | works |
| `curl :8082/druid/v2/sql` (broker, no credentials) | **200, query runs** | 303 to IdP |
| `curl :8081/...` (coordinator, no credentials) | **200** | 302 to IdP |
| Identity the broker sees for a console query | `allowAll` (anonymous) | `0b46f85b-...` (alice's `sub`) |
| Internal service-to-service traffic | unauthenticated | `basic` escalator (`druid_system`) |

Broker request log (`druid.request.logging.type=slf4j`) for a console query in the `oidc-all` setup:

```
LoggingRequestLogger - ... {"query/time":11,"success":true,"statusCode":200,"identity":"0b46f85b-79d3-49d6-a684-fd0fb05b48b7"} {"queryType":"scan","dataSource":{"type":"inline","columnNames":["marker"],...,"rows":[["via-router"]]}...
```

So the router isn't special in the code. It's just the service browsers should reach, because the console is served
from there and it's the address you register as the redirect URI. A better wording of the docs: "Users should reach
the web console through the router. To authorize per user, every service that receives proxied console requests must
also run pac4j with the same `cookiePassphrase`, behind an authenticator for internal traffic."

### 4. The session cookie is a portable bearer token

- Taking the cookies from the router login and sending them **directly to the broker** (`:8082`) → `200`. Sending
  **only** `pac4j.session.pac4jUserProfiles` to the coordinator (`:8081`) → `200`. Any service with the same passphrase
  accepts it until it expires. `JSESSIONID` isn't needed.
- Consequences: no server-side revocation and no logout (the extension has no logout endpoint). The
  `cookiePassphrase` is effectively the signing key for every session. The docs' warning about a strong passphrase
  (CVE-2024-45384) is the right instinct, but the docs don't explain *why* it matters this much.

### 5. `clientAuthenticationMethod`: only 2 of the 6 documented values work, and the default broke

**What the setting is:** how the router authenticates *itself* to the IdP's token endpoint when it exchanges the login
`code` for tokens. This is a server-to-server call the browser never sees. It has **nothing to do with the browser
session**: whichever method you pick, the session is the same encrypted `pac4j.session.pac4jUserProfiles` cookie.

**Results** against Keycloak 26.0.7, one throwaway router per value, with a Keycloak client set up to give each value a
fair chance ([`scripts/client_auth_methods.sh`](scripts/client_auth_methods.sh),
[full log](evidence/client-auth-methods-run.log)):

| `clientAuthenticationMethod` | Keycloak client | Result |
|---|---|---|
| *(unset, auto-detect)* | confidential (`druid`) | ❌ `500 privateKeyJwtConfig cannot be null` |
| `client_secret_basic` | confidential (`druid`) | ✅ login + proxied SQL work |
| `client_secret_post` | confidential (`druid`) | ✅ login + proxied SQL work |
| `client_secret_jwt` | signed-JWT-with-secret (`druid-jwt`) | ❌ `500 Configured authentication method (client_secret_jwt) is not supported.` |
| `private_key_jwt` | confidential (`druid`) | ❌ `500 privateKeyJwtConfig cannot be null` |
| `none` | public (`druid-public`) | ❌ `500 Preferred authentication method (none) not supported by provider according to provider metadata (...)` |
| `none` | confidential (`druid`) | ❌ same as above |

Why each failure happens (from pac4j's bytecode: `OidcAuthenticator` in pac4j-oidc 4.5.7 and 5.8.0):

- **`client_secret_jwt`**: pac4j doesn't implement it. Its supported set is `{post, basic, none}` in 4.5.7 and
  `{post, basic, private_key_jwt, none}` in 5.8.0. The docs list a value that can never work.
- **`private_key_jwt`**: pac4j needs a `PrivateKeyJWTClientAuthnMethodConfig` (private key, key ID, JWS algorithm), and
  Druid has no properties to provide one. It can never work in Druid.
- **`none`**: pac4j rejects an explicitly configured method unless the IdP's discovery document lists it, and Keycloak's
  doesn't list `none`. It might work with an IdP that advertises `none` (not tested). Druid also still requires
  `clientSecret` for it.
- **auto-detect (the default) is a regression from the pac4j 5 upgrade
  ([#18259](https://github.com/apache/druid/pull/18259)).** With no explicit method, pac4j takes the **first** entry of
  the IdP's `token_endpoint_auth_methods_supported` that's in its supported set. Druid never calls
  `setSupportedClientAuthenticationMethods`, so pac4j's own default set is used.
  - On 4.5.7 that set had no `private_key_jwt`, so Keycloak got `client_secret_basic`.
  - On 5.8.0 it does, so Keycloak (which lists `private_key_jwt` first) gets a method Druid can't configure.

  [#19020](https://github.com/apache/druid/pull/19020) (April 2026) added `clientAuthenticationMethod` as the
  workaround, but the docs don't connect it to this failure.

Which IdPs auto-detect breaks for depends only on the order of that list. Public discovery documents on 2026-10-19:

| IdP | `token_endpoint_auth_methods_supported` (in order) | auto picks |
|---|---|---|
| Keycloak 26 | `private_key_jwt, client_secret_basic, client_secret_post, tls_client_auth, client_secret_jwt` | `private_key_jwt` ❌ |
| Google | `client_secret_post, client_secret_basic` | `client_secret_post` ✅ |
| Microsoft Entra ID | `client_secret_post, private_key_jwt, client_secret_basic, self_signed_tls_client_auth` | `client_secret_post` ✅ |
| GitLab.com | `client_secret_basic, client_secret_post` | `client_secret_basic` ✅ |

How the failure shows up: the router starts healthy. Every login attempt then shows the user a raw Jetty `HTTP ERROR
500` page. The router logs only a Jetty `WARN ... HttpChannel - /unified-console.html` line with the pac4j exception on
the next line, and no `ERROR`.

### 6. The Druid identity is always `sub`; `oidcClaim` doesn't apply

`Pac4jFilter` uses `profile.getId()` (the `sub` claim, a UUID in Keycloak) as the identity. `druid.auth.pac4j.oidc.oidcClaim`
is only read by `JwtAuthFilter` (the `jwt` authenticator). The docs present `oidcClaim` as a general setting, so
authorizer rules written for `alice` won't match a pac4j web login.

### 7. Regression: user profile no longer passed to authorizers

[#16109](https://github.com/apache/druid/pull/16109) put the pac4j `UserProfile` into `AuthenticationResult.context`
(`{"profile": ...}`) so authorizers like OPA could use claims. The pac4j upgrade in
[#18259](https://github.com/apache/druid/pull/18259) rewrote `Pac4jFilter` and now passes `null`
(`git log -S'ImmutableMap.of("profile"' -- extensions-core/druid-pac4j` shows both commits).

### 8. About 40 ms of extra latency per request

Every authenticated request decrypts the session cookies and re-issues three encrypted CSRF cookies, and each encrypt/decrypt in Druid's `CryptoService`
derives a fresh key with PBKDF2 (65536 iterations, random salt per encryption):

```
coordinator direct             ~0.003 s
same call via router + pac4j   ~0.043 s
```

The console makes many parallel requests (e.g. the Services/Segments views), so this adds up. The CSRF tokens
aren't even checked: `Pac4jFilter` passes authorizers `"none"` ("to avoid CSRF issues").

### 9. Cookies are always `Secure`

`Pac4jSessionStore` always sets `Secure` (and logs a warning on plain HTTP). Chromium accepts `Secure` cookies on
`http://localhost`, which is how this setup works. On any other plain-HTTP host, browsers drop them per the cookie
spec, so login would loop (expected from the spec, not tested here). The docs should say HTTPS is required (except
localhost).

### 10. Smaller code observations

- `Pac4jFilter` reads `pac4j.originalUrl` from the `HttpSession` for the post-login redirect, but nothing ever sets it.
  The redirect actually works through pac4j's own `pac4jRequestedUrl` cookie.
- `Pac4jSessionStore.set` also writes every value into the Jetty `HttpSession` (hence `JSESSIONID`), even though reads
  only use cookies.
- There are no integration tests for pac4j at all (only unit tests with mocks).
- `OIDCConfig` defaults `oidcClaim` to a constant named `DEFAULT_SCOPE` (value `"name"`). The behavior is right, but
  the name is misleading next to the real `scope` property.

## ToDos

### Web console

- [ ] Send `X-Requested-With: XMLHttpRequest` on all API requests (`Api.getDefaultConfig()`), so an expired session
      becomes a detectable `401` instead of an opaque "Network Error". Verified with pac4j. It should be harmless for
      other authenticators, but double-check `basic` (a `WWW-Authenticate: Basic` 401 on XHR can trigger the browser's
      native prompt; that is existing behavior).
- [ ] Add a global axios response interceptor: on `401` (especially with `WWW-Authenticate: Bearer realm="pac4j"`),
      show a single "Your session has expired" dialog with a **Sign in again** button, instead of per-view errors with
      HTML bodies. Deduplicate the many parallel failures into one dialog.
- [ ] Decide how "Sign in again" works:
  - simplest: `window.location.reload()` (loses in-memory state: results, running-query tracking, open dialogs);
  - nicer: open the console URL in a **popup**, which goes through the IdP and sets fresh cookies shared with the
    original tab. When it lands back on the console, close it and retry the failed requests. Nothing lost. (A hidden
    iframe is less likely to work: IdPs usually forbid framing.)
- [ ] Until the above exists, make the generic "Network Error" message more helpful for same-origin requests, e.g.
      "...this can happen when your login session expires; try reloading the page."
- [ ] Before reloading, warn if queries are running or there is unsaved state (ingestion spec being edited, etc.), and
      make sure everything worth keeping is in `localStorage`.
- [ ] Show the signed-in user and offer **Log out** (needs backend support, see below).

### Documentation (`docs/development/extensions-core/druid-pac4j.md`)

- [ ] Rewrite the "only be used at the router node" sentence (and add the missing "the"). Explain that browsers should
      use the router, and that services behind it need pac4j too (same passphrase), with another authenticator such as
      `basic` first in the chain for internal traffic, or else they're unauthenticated and see no user identity.
- [ ] Add a complete, working example: router + common config, authenticator chain, escalator, authorizer
      (see [`druid/all-services.properties`](druid/all-services.properties)).
- [ ] Document the **redirect/callback URI** to register with the IdP: `https://<router>/druid-ext/druid-pac4j/callback`.
      The page never mentions it.
- [ ] Document `druid.auth.authenticator.<name>.authorizerName` (needed, missing from the table).
- [ ] Fix the "Creating an Authenticator" snippet: it sets `druid.auth.authenticatorChain` twice (`["pac4j"]` then
      `["jwt"]`), so a copy-paste keeps only `jwt`. Show them as alternatives or as one chain.
- [ ] Say that `oidcClaim` applies only to the `jwt` authenticator; for pac4j the identity is `sub`.
- [ ] Fix the `clientAuthenticationMethod` row: only `client_secret_basic` and `client_secret_post` work.
      `client_secret_jwt` isn't implemented by pac4j, `private_key_jwt` can't be configured in Druid, and `none` needs
      the IdP to advertise it. Recommend setting it explicitly, explain that it only affects the router↔IdP back
      channel, and mention the Keycloak `privateKeyJwtConfig cannot be null` error.
- [ ] Document session behavior: lifetime = min(IdP token lifetime, 15 min), not extended by activity, no logout,
      re-login is silent while the IdP session lasts.
- [ ] Document that HTTPS is required (cookies are always `Secure`), localhost excepted.
- [ ] Explain what the `cookiePassphrase` protects (it decrypts *and creates* sessions on every service), and recommend a
      [password provider](https://druid.apache.org/docs/latest/operations/password-provider).
- [ ] Consider adding a short "Using OIDC with the web console" section to `operations/web-console.md` linking here.

### `druid-pac4j` extension (for discussion with maintainers)

- [ ] Restore `AuthenticationResult` context with the user profile (regression from #18259).
- [ ] Restore pre-#18259 auto-detection: call `oidcConf.setSupportedClientAuthenticationMethods(...)` without
      `PRIVATE_KEY_JWT` (Druid can't configure it), or default to `client_secret_basic` when unset.
- [ ] Validate `clientAuthenticationMethod` at startup and fail fast for values that can't work, instead of a 500 on
      every login. Make `clientSecret` optional when the method is `none`.
- [ ] Log OIDC configuration failures at `ERROR` from the pac4j filter, not only as Jetty's generic `WARN`.
- [ ] Let the identity come from a configurable claim (reuse `oidcClaim` or add a new property) instead of always `sub`.
- [ ] Make the session cookie max age configurable (and consider re-issuing it on activity).
- [ ] Remove the per-request cost: stop generating CSRF cookies nobody checks and/or cache derived keys in `CryptoService` usage.
- [ ] Add a logout endpoint (clear cookies, optionally RP-initiated logout at the IdP) and a "who am I" endpoint for the
      console.
- [ ] Remove the dead `pac4j.originalUrl` lookup and the unneeded `HttpSession` writes.
- [ ] Add an integration test with a real IdP (Keycloak in Docker, like this repo).

## Reproduce it

### Prerequisites

- Docker
- A built Druid distribution, e.g. from a Druid checkout: `mvn clean install -Pdist -T1C -DskipTests`, which produces
  `distribution/target/apache-druid-<version>`
- Python 3 (for the scripted flow) and Node.js (for the browser test)

### 1. Start the mock OIDC provider

```bash
docker compose up -d     # Keycloak on http://localhost:18080, realm "druid" imported from keycloak/
```

The `druid` realm ([`keycloak/druid-realm.json`](keycloak/druid-realm.json)) contains:

| What | Value |
|---|---|
| OIDC client | `druid` / secret `druid-client-secret` (confidential), redirect URIs `http://localhost:8888/*` and `:9888/*` |
| Extra clients | `druid-jwt` (signed JWT with secret) and `druid-public` (public), only used by `scripts/client_auth_methods.sh` |
| User | `alice` / `alice` (Alice Admin, alice@example.com) |
| User | `bob` / `bob` (Bob Reader, bob@example.com) |
| Token lifetime | **120 s** (deliberately short so expiry is easy to observe; Keycloak's default is 300 s) |
| Keycloak admin console | http://localhost:18080/admin, `admin` / `admin` (master realm) |

The users have no roles; with the `allowAll` authorizer the names are just labels.

### 2. Configure and start Druid

```bash
./druid/setup-conf.sh /path/to/apache-druid-<version>   # creates conf/druid/oidc-router-only and conf/druid/oidc-all
cd /path/to/apache-druid-<version>
bin/start-druid -m 6g -c conf/druid/oidc-all            # or conf/druid/oidc-router-only
```

The `oidc-all` config also creates Druid basic-auth users `admin` / `admin` and `druid_system` / `internal` (internal
traffic). These bypass OIDC, e.g. `curl -u admin:admin http://localhost:8082/...`.

### 3. Try it

- Browser: open http://localhost:8888 in **Chrome** and log in as `alice` / `alice`. Wait 2+ minutes, click around,
  and watch "Network Error"; reload and you're back in without a password.
- Scripted login, printing every redirect and cookie
  ([sample output](evidence/oidc-flow-run.log)):

  ```bash
  python3 scripts/oidc_flow.py alice alice /status "POST /druid/v2/sql {\"query\":\"SELECT 1\"}"
  python3 scripts/oidc_flow.py --reuse /status    # reuse the saved cookies later, e.g. after expiry
  ```

- Real-browser expiry test (about 3 minutes; writes screenshots to `evidence/`):

  ```bash
  cd scripts && npm install && npx playwright install chromium && node browser_expiry.js
  ```

- Every `clientAuthenticationMethod` value (about 4 minutes; starts a throwaway router per value on `:9888` next to the
  running `oidc-all` cluster):

  ```bash
  scripts/client_auth_methods.sh /path/to/apache-druid-<version>
  ```

- Probes used for the router question:

  ```bash
  curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8888/druid/coordinator/v1/leader                                # 302 (to IdP)
  curl -s -o /dev/null -w '%{http_code}\n' -H 'X-Requested-With: XMLHttpRequest' http://localhost:8888/druid/coordinator/v1/leader  # 401
  curl -s -H 'Content-Type: application/json' -d '{"query":"SELECT 1"}' http://localhost:8082/druid/v2/sql                  # open in router-only, 303 in all
  ```

### Cleanup

```bash
docker compose down
# stop Druid with Ctrl-C in the start-druid terminal
```

## Repo layout

```
docker-compose.yml           Keycloak (mock IdP)
keycloak/druid-realm.json    realm: client "druid", users alice and bob
druid/setup-conf.sh          builds the two Druid configs from a distribution's conf/druid/auto
druid/router-only.properties config overlay: pac4j on the router only (docs as written)
druid/all-services.properties config overlay: basic + pac4j on every service
scripts/oidc_flow.py         stdlib-only scripted login that prints every hop
scripts/browser_expiry.js    Playwright test: login, expiry, X-Requested-With probe, reload
scripts/client_auth_methods.sh  tries every clientAuthenticationMethod value on a throwaway router
evidence/                    logs and screenshots from the runs described above
```
