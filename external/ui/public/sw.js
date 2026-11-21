/*
 * Coddy's service worker, registered by src/ui/pwa/serviceWorker.ts at the
 * root of the page, so its scope is the whole web UI.
 *
 * It caches nothing and has no fetch handler: every request goes to the
 * server as it would without it, so a new build is never hidden behind an old
 * copy. It exists for two things a page cannot do on its own:
 *
 * - show a notification where the page cannot construct one (Chrome on
 *   Android) and decide, across every tab of the app, whether one is needed at
 *   all: a tab asks with a "coddy-notify" message, and nothing is shown while
 *   any window of the app has the focus, or twice for the same tag when
 *   several tabs heard the same event;
 * - open the chat a notification is about when it is clicked: the tab that
 *   asked (or any tab of the app) is focused and told which session to open
 *   with a "coddy-open" message, and with no tab left a new window opens on
 *   the chat's address;
 * - show what the server pushes while no tab is open (Web Push, level two of
 *   the notifications, external/httpserver/push.go). Every push is shown,
 *   since a browser revokes a subscription that receives silent ones; a
 *   permission notice carries Allow and Reject, which answer it from the
 *   notification, and the worker tells the server when a push arrived, which
 *   is how delivery time is measured.
 *
 * Contract: DESIGN.md, "Installable app and notifications".
 */

const NOTIFY = "coddy-notify";
const OPEN = "coddy-open";

/** How long a tag counts as shown: the tabs of one browser hear an event at once. */
const SHOWN_TAG_MS = 30 * 1000;

/** Tags shown lately, by the time they were shown. */
const shownTags = new Map();

self.addEventListener("install", () => {
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener("message", (event) => {
  const msg = event.data;
  if (!msg || msg.type !== NOTIFY || typeof msg.title !== "string") {
    return;
  }
  const source = event.source && event.source.id ? event.source.id : "";
  event.waitUntil(showForTab(msg, source));
});

async function showForTab(msg, sourceId) {
  const windows = await self.clients.matchAll({
    type: "window",
    includeUncontrolled: true,
  });
  if (windows.some((client) => client.focused)) {
    return;
  }
  const tag = typeof msg.tag === "string" ? msg.tag : "";
  if (tag) {
    const now = Date.now();
    for (const [seen, at] of shownTags) {
      if (now - at > SHOWN_TAG_MS) shownTags.delete(seen);
    }
    if (shownTags.has(tag)) {
      return;
    }
    shownTags.set(tag, now);
  }
  const options = {
    body: typeof msg.body === "string" ? msg.body : "",
    icon: "/icon-192.png",
    data: {
      url: typeof msg.url === "string" ? msg.url : "/",
      sessionId: typeof msg.sessionId === "string" ? msg.sessionId : "",
      env: typeof msg.env === "string" ? msg.env : "",
      client: sourceId,
    },
  };
  if (tag) options.tag = tag;
  if (typeof msg.lang === "string" && msg.lang) options.lang = msg.lang;
  await self.registration.showNotification(msg.title, options);
}

self.addEventListener("push", (event) => {
  event.waitUntil(showPushed(event));
});

async function showPushed(event) {
  const receivedAt = Date.now();
  let notice = {};
  try {
    notice = event.data ? event.data.json() : {};
  } catch {
    notice = {};
  }
  const title =
    typeof notice.title === "string" && notice.title ? notice.title : "Coddy";
  const tag = typeof notice.tag === "string" ? notice.tag : "";
  const data = {
    url: typeof notice.url === "string" ? notice.url : "/",
    sessionId: typeof notice.sessionId === "string" ? notice.sessionId : "",
    env: "local",
    client: "",
    kind: typeof notice.kind === "string" ? notice.kind : "",
    sentAt: typeof notice.sentAt === "number" ? notice.sentAt : 0,
    toolCallId: typeof notice.toolCallId === "string" ? notice.toolCallId : "",
    allow: typeof notice.allow === "string" ? notice.allow : "",
    reject: typeof notice.reject === "string" ? notice.reject : "",
    device: typeof notice.device === "string" ? notice.device : "",
  };
  const options = {
    body: typeof notice.body === "string" ? notice.body : "",
    icon: "/icon-192.png",
    badge: "/icon-192.png",
    data,
  };
  if (tag) {
    options.tag = tag;
    options.renotify = true;
    // A tab of this browser that already showed the same occurrence wins.
    shownTags.set(tag, receivedAt);
  }
  if (typeof notice.lang === "string" && notice.lang)
    options.lang = notice.lang;
  if (data.kind === "permission" && data.toolCallId && data.allow) {
    const ru = typeof notice.lang === "string" && notice.lang.startsWith("ru");
    options.actions = [
      { action: "allow", title: ru ? "Разрешить" : "Allow" },
      { action: "reject", title: ru ? "Отклонить" : "Reject" },
    ];
    options.requireInteraction = true;
  }
  await self.registration.showNotification(title, options);
  await sendReceipt({
    tag,
    kind: data.kind,
    device: data.device,
    sentAt: data.sentAt,
    receivedAt,
  });
}

async function sendReceipt(body) {
  try {
    await fetch("/coddy/push/receipt", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      credentials: "same-origin",
    });
  } catch {
    /* a receipt is a measurement, never a reason to fail the notice */
  }
}

self.addEventListener("pushsubscriptionchange", (event) => {
  event.waitUntil(resubscribe(event));
});

async function resubscribe(event) {
  // The push service replaced the endpoint: subscribe again with the same key
  // and hand the new endpoint over; the server drops the old one at its 410.
  try {
    const old = event.oldSubscription;
    const key = old && old.options ? old.options.applicationServerKey : null;
    if (!key) return;
    const sub = await self.registration.pushManager.subscribe({
      userVisibleOnly: true,
      applicationServerKey: key,
    });
    const json = sub.toJSON();
    await fetch("/coddy/push/subscriptions", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ endpoint: json.endpoint, keys: json.keys }),
      credentials: "same-origin",
    });
  } catch {
    /* the next visit of the app subscribes again */
  }
}

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const data = event.notification.data || {};
  if (
    (event.action === "allow" || event.action === "reject") &&
    data.toolCallId
  ) {
    event.waitUntil(answerFromNotification(event.action, data));
    return;
  }
  event.waitUntil(openFromNotification(data));
});

async function answerFromNotification(action, data) {
  const optionId = action === "allow" ? data.allow : data.reject;
  let ok = false;
  try {
    const res = await fetch(
      `/coddy/sessions/${encodeURIComponent(data.sessionId)}/permission`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          toolCallId: data.toolCallId,
          optionId: optionId || action,
        }),
        credentials: "same-origin",
      },
    );
    ok = res.ok;
  } catch {
    ok = false;
  }
  await sendReceipt({
    kind: data.kind,
    device: data.device,
    sentAt: data.sentAt,
    action: ok ? action : action + "-failed",
  });
  if (!ok) {
    // Answered elsewhere already, or the server is out of reach: the chat
    // shows what happened.
    await openFromNotification(data);
  }
}

async function openFromNotification(data) {
  const windows = await self.clients.matchAll({
    type: "window",
    includeUncontrolled: true,
  });
  const target =
    windows.find((client) => client.id === data.client) || windows[0];
  if (target) {
    try {
      await target.focus();
    } catch {
      /* a browser may refuse; the message still opens the chat */
    }
    target.postMessage({
      type: OPEN,
      sessionId: data.sessionId || "",
      env: data.env || "",
    });
    return;
  }
  await self.clients.openWindow(data.url || "/");
}
