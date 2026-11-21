# Plan: a phone that pairs by QR code and answers the agent from a notification (MVP)

Status: MVP on branch `feat/mobile-mvp`, tested on a real Android phone on 2026-11-22, not merged.
It implements phases 2a and 2c of [pwa-push-notifications.md](pwa-push-notifications.md),
reduced to one person, and adds pairing a phone by QR code, which that plan does not cover. This
record keeps what was built, what was measured and what the maintainers still have to decide.

## 1. The problem

A turn that asks for a permission waits for an answer with no timeout
(`Sender.RequestPermission` in `external/httpserver/bridge.go` selects on the answer and on the
turn's context only). When the person is away from the computer, the agent stands still until they
come back.

A phone does not help today:

- the notifications of the web UI come from an open tab (level one); on a phone the tab is gone or
  asleep as soon as Coddy leaves the screen. Measured on Android with Coddy 1.4.38: with the app
  closed, and with it only minimized, nothing reached the locked phone in three runs out of three;
- reaching the computer from the phone needs a credential and a TLS proxy, and the phone signs in
  with a typed password.

## 2. The scenario

1. On the computer, **Settings, Phone** shows a QR code.
2. The phone scans it; Coddy opens in Chrome and the phone is paired, with no password.
3. The phone adds Coddy to its home screen and turns on **Also when Coddy is closed**.
4. Later the agent asks for a permission while no tab of Coddy has anyone's attention: the locked
   phone shows "Permission needed: run_command" with **Allow** and **Reject**.
5. **Allow** in the notification answers the prompt; the app does not open. The turn goes on, and
   a second notice says it finished.

## 3. What was built

### 3.1 Pairing (`external/httpserver/devices.go`)

- `POST /coddy/devices/pairing` mints a code of 8 characters (an alphabet without 0/O, 1/I/L) and
  the QR code of `<address>/#/pair/<code>`. The address is the request's `baseUrl`, else the new key
  `httpserver.public_url`, else the origin of the request. The code is in the fragment, so it never
  reaches a server log or a referrer.
- A code lives 10 minutes and opens at most two browsers: on iPhone the app on the home screen keeps
  cookies apart from Safari. Twenty wrong codes close every open code; at most eight are open.
- `POST /coddy/auth/pair` redeems a code and sets the device cookie (HttpOnly, SameSite=Strict,
  Secure behind TLS, named per host like the sign-in cookie). The token is kept as a SHA-256 digest
  in `<home>/devices.json` (0600), so a paired phone survives a restart; a device unused for 90 days
  is forgotten. `GET /coddy/devices` lists them, `DELETE /coddy/devices/{id}` unpairs one and drops
  its push subscriptions.
- **The guard changes.** An open server (no token, no sign-in) reached on loopback under another
  name than localhost answered 421 to everything (`openServerGuard`). It now answers the page and
  the sign-in routes, the API only to a paired device's cookie, and 401 otherwise, so a phone behind
  a proxy (a TLS proxy on the LAN, a tailnet name, a tunnel) can pair. Writes from another origin are
  refused as before. `features/open_server_guard.feature` moves from 421 to 401 for that case.
- `GET /coddy/auth/me` says `pair_login` and, for such a request, `pair_required`; the sign-in screen
  then shows a field for the code next to (or instead of) the password form.

### 3.2 Push (`external/httpserver/push.go`, `internal/webpush`)

- `internal/webpush`: RFC 8291 `aes128gcm` (the example of the RFC reproduced byte for byte), RFC 8292
  VAPID, the send with `TTL`, `Urgency`, `Topic`. Standard library only, about 420 lines.
- What is worth a notice: a turn's end (the manager's turn observer), a permission prompt and a
  question (callbacks of the HTTP `Sender`, the senders of woken turns included).
- Who gets it: every subscription, when a browser prompted the session and no device reported
  attention in the last 90 seconds (`POST /coddy/presence`, sent on focus, blur, visibility and
  `pagehide`, and every 60 seconds while attentive).
- The payload is the notice of a tab, with the same tag (`coddy:local:<session>:<kind>:<key>`), so a
  push and a tab's notice on one device replace each other; a permission carries the tool call and
  the option ids of Allow and Reject. `Urgency: high` for a permission or a question. Every
  subscription is sent to at once; 404 and 410 remove it.
- `POST /coddy/push/receipt` (diagnostics of the MVP): the service worker reports when a push
  arrived and which button answered it, and a page that cannot subscribe reports what the browser
  offers. The server logs the delay on its own clock.

### 3.3 The browser side

- `public/sw.js`: `push` shows every push (Chrome and Safari revoke silent subscriptions);
  `notificationclick` with `allow` or `reject` posts to `/coddy/sessions/{id}/permission`, otherwise
  opens the chat; `pushsubscriptionchange` subscribes again.
- **Settings, Phone** (`src/ui/pwa/PhoneSection.tsx`): the address the phone opens, the QR code and
  the code, the push switch with a test notice, the paired devices.
- `src/ui/auth`: the `#/pair/<code>` link redeems its code before any form and takes it out of the
  address; `PairCodeCard` takes a typed code.

### 3.4 Routes

| Route | Gate |
| --- | --- |
| `GET /coddy/push/key`, `GET/POST /coddy/push/subscriptions`, `DELETE /coddy/push/subscriptions/{id}`, `POST /coddy/push/test`, `POST /coddy/push/receipt`, `POST /coddy/presence` | the API's |
| `POST /coddy/devices/pairing`, `GET /coddy/devices`, `DELETE /coddy/devices/{id}` | the API's |
| `POST /coddy/auth/pair` | open, like the other sign-in routes |

`openapi.go` and `docs/reference/http-api.md` are not updated yet (section 8).

## 4. Measurements

The stand: a scripted model whose first answer calls `run_command`, so every turn asks for the same
permission; the MVP and Coddy 1.4.38 side by side on their own homes and addresses
(`https://<LAN>:8443` and `:8444` through Caddy with its own certificate authority); one Android
phone in the same network. Times are on the server's clock: the phone's clock ran 1.2-1.3 s ahead.

| | MVP | Coddy 1.4.38 |
| --- | --- | --- |
| A notice reaches the locked phone with Coddy closed | yes, 3 runs of 3 | no, 3 runs of 3 (closed, minimized, closed) |
| Permission push, accepted by FCM | 65-262 ms | - |
| Permission push, on the locked phone | 0.8 s (clean run); 0.8-9.2 s over three runs | - |
| How the person answers | Allow in the notification | open Coddy |
| How long the agent waited for the person | 7.5 s (clean run); 15.6 s and 24.0 s before | 120 s, until the test answered from the computer; unbounded otherwise |
| "Turn finished" push, on the phone | 0.25-0.3 s | - |

Desktop Chrome subscribed through FCM, every tab closed: a push reached the browser 75-106 ms after
it was sent, and **Allow** on the desktop notification resumed the turn. The first push after the
server started once took 5.2 s, all of it the first connection to FCM; later fresh connections took
146 ms.

## 5. Findings on Android

1. **Nearby devices.** Chrome opened the address on the LAN only after it was given the Android
   permission "Nearby devices"; before, the scanner opened Chrome's "App info" page instead.
2. **A private certificate authority** installs only through **Settings, CA certificate**; opening
   the downloaded file says it must be installed in Settings. Until it is, Chrome refuses the service
   worker ("An SSL certificate error occurred when fetching the script") while the page itself
   opens, so the app cannot be installed and nothing is pushed.
3. **The system camera** handed the link to Chrome badly on the test phone; Chrome's own scanner
   (Google Lens in the address bar) opened it.
4. **One phone, two subscriptions** can happen (a Chrome tab and the installed app keep separate
   storage, hence two device ids). They have to be merged.
5. Chrome on Android reports its model as `K`; the device is named from the user agent client hints.

A route with a certificate the phone already trusts (a tailnet name, a domain with Let's Encrypt, a
relay) avoids findings 1 and 2. Without one, Coddy could serve HTTPS on the LAN itself and show two
QR codes in **Settings, Phone**: install the certificate, then pair.

## 6. Simplifications of the MVP

- One person: every subscription follows every chat a browser prompted, and attention on any device
  silences every push (the plan keys both by principal, section 3.2 and 3.3 of the push plan).
- Followers live in memory, not in `session.json`; a turn's end is always "finished", its outcome is
  not known here yet.
- `httpserver.push.enable` and `httpserver.push.subject` are not there: pushes are on, the VAPID
  subject is `https://coddy.dev`.
- The receipt route and the browser diagnostics exist for the measurements.
- iPhone was not tested.

## 7. Decisions for the maintainers

- The guard change of 3.1: an open server answering the page and the sign-in routes under any name
  that reaches it through loopback, the API to paired devices only.
- Pairing as a credential of its own next to the token and the sign-in form, and whether a paired
  device may pair further devices.
- Four questions of section 8 of the push plan (defaults of the Telegram notices and of
  `httpserver.push.enable`, the VAPID subject, 2b or 2c first).
- Whether the receipts stay as an opt-in diagnostic or go.
- Which route the documentation recommends to a phone: a tailnet, a domain, a relay, or HTTPS on the
  LAN served by Coddy with its certificate offered by QR code.

## 8. Before a pull request

- `openapi.go`, `docs/reference/http-api.md`, a page under `docs/features/` with its Russian
  translation and screenshots, `DESIGN.md` for the Phone tab and the notification buttons.
- Subscriptions and attention by principal, followers in `session.json`, the outcome of a turn.
- `httpserver.push.*` keys through the schema, the field tables, `config.example.yaml`, the
  `configure-coddy` skill and the site copy of the schema.
- Merging the subscriptions of one device; vitest for the `push` and `notificationclick` handlers
  of `sw.js` and for the Phone tab.
- An iPhone run.
