// Level two of the notifications: Web Push through the push service of the
// browser's vendor, so a notice reaches this device with every tab of Coddy
// closed (a phone asleep in a pocket). The server decides when one is due
// (external/httpserver/push.go): the agent finished a turn, asks for a
// permission or asks a question, and no tab of Coddy has anyone's attention.
// This module subscribes the browser, reports whether this tab has the
// person's attention, and asks for a test notice.
//
// Design: docs/plans/pwa-push-notifications.md (phase 2c).

import { getEnv, localFetch } from "../env/remoteEnv";
import { pageHasAttention } from "./notifications";

const DEVICE_KEY = "coddy_device_id";
const SUBSCRIPTION_KEY = "coddy_push_subscription";

/** How often an attentive tab repeats its report; the server keeps one 90 s. */
const PRESENCE_EVERY_MS = 60 * 1000;

export type PushSupport =
  | "ready"
  | "unsupported"
  | "insecure"
  | "install"
  | "denied"
  | "remote";

function storage(): Storage | null {
  try {
    return typeof window !== "undefined" ? window.localStorage : null;
  } catch {
    return null;
  }
}

/** deviceId names this browser for the server, the same id in every tab. */
export function deviceId(): string {
  const store = storage();
  let id = store?.getItem(DEVICE_KEY) ?? "";
  if (!id) {
    const bytes = new Uint8Array(12);
    crypto.getRandomValues(bytes);
    id = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
    store?.setItem(DEVICE_KEY, id);
  }
  return id;
}

/** isIOS reports an iPhone or an iPad, whose Safari pushes only to an installed app. */
export function isIOS(): boolean {
  if (typeof navigator === "undefined") {
    return false;
  }
  const ua = navigator.userAgent || "";
  return (
    /iPhone|iPad|iPod/.test(ua) ||
    (ua.includes("Macintosh") && navigator.maxTouchPoints > 1)
  );
}

/** isStandalone reports the web UI opened as an installed app. */
export function isStandalone(): boolean {
  if (typeof window === "undefined") {
    return false;
  }
  const nav = navigator as Navigator & { standalone?: boolean };
  return (
    nav.standalone === true ||
    (typeof window.matchMedia === "function" &&
      window.matchMedia("(display-mode: standalone)").matches)
  );
}

/** pushSupport says whether this browser can be subscribed here, or why not. */
export function pushSupport(): PushSupport {
  if (typeof window === "undefined") {
    return "unsupported";
  }
  if (getEnv().mode !== "local") {
    return "remote";
  }
  if (!window.isSecureContext) {
    return "insecure";
  }
  if (isIOS() && !isStandalone()) {
    return "install";
  }
  if (
    !("serviceWorker" in navigator) ||
    !("PushManager" in window) ||
    typeof Notification === "undefined"
  ) {
    return "unsupported";
  }
  if (Notification.permission === "denied") {
    return "denied";
  }
  return "ready";
}

const listeners = new Set<() => void>();

function emit(): void {
  for (const listener of [...listeners]) listener();
}

export function subscribePushState(onChange: () => void): () => void {
  listeners.add(onChange);
  return () => {
    listeners.delete(onChange);
  };
}

/** pushStateSnapshot drives useSyncExternalStore: "on" or "off", then the support. */
export function pushStateSnapshot(): string {
  return `${storage()?.getItem(SUBSCRIPTION_KEY) ? "on" : "off"}:${pushSupport()}`;
}

function base64UrlToBytes(value: string): Uint8Array<ArrayBuffer> {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/");
  const raw = atob(padded + "=".repeat((4 - (padded.length % 4)) % 4));
  const out = new Uint8Array(new ArrayBuffer(raw.length));
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

function bytesToBase64Url(buf: ArrayBuffer | null): string {
  if (!buf) return "";
  let s = "";
  for (const b of new Uint8Array(buf)) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function serverKey(): Promise<string> {
  const res = await localFetch("/coddy/push/key", {
    headers: { Accept: "application/json" },
  });
  if (!res.ok) {
    throw new Error(`push key: ${res.status}`);
  }
  const body = (await res.json()) as { enabled?: boolean; publicKey?: string };
  if (!body.enabled || !body.publicKey) {
    throw new Error("push is off on this server");
  }
  return body.publicKey;
}

export type PushResult = { ok: true } | { ok: false; reason: string };

/**
 * enablePush runs from a click: it asks for the permission when it was not
 * given yet, subscribes the browser with the server's key and hands the
 * subscription to the server.
 */
export async function enablePush(): Promise<PushResult> {
  const support = pushSupport();
  if (support !== "ready") {
    return { ok: false, reason: support };
  }
  try {
    if (Notification.permission === "default") {
      const answer = await Notification.requestPermission();
      if (answer !== "granted") {
        emit();
        return {
          ok: false,
          reason: answer === "denied" ? "denied" : "default",
        };
      }
    }
    const key = await serverKey();
    const reg = await navigator.serviceWorker.ready;
    let sub = await reg.pushManager.getSubscription();
    if (sub) {
      // A subscription made for another key (a server whose key changed)
      // would never deliver: subscribe again.
      const current = bytesToBase64Url(sub.options.applicationServerKey);
      if (current && current !== key.replace(/=+$/, "")) {
        await sub.unsubscribe();
        sub = null;
      }
    }
    sub ??= await reg.pushManager.subscribe({
      userVisibleOnly: true,
      applicationServerKey: base64UrlToBytes(key),
    });
    const json = sub.toJSON() as {
      endpoint?: string;
      keys?: { p256dh?: string; auth?: string };
    };
    const res = await localFetch("/coddy/push/subscriptions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({
        endpoint: json.endpoint,
        keys: json.keys,
        device: deviceId(),
        lang:
          typeof document !== "undefined" ? document.documentElement.lang : "",
      }),
    });
    if (!res.ok) {
      return { ok: false, reason: `server ${res.status}` };
    }
    const stored = (await res.json()) as { id?: string };
    storage()?.setItem(SUBSCRIPTION_KEY, stored.id || "1");
    emit();
    return { ok: true };
  } catch (err) {
    emit();
    return {
      ok: false,
      reason: err instanceof Error ? err.message : String(err),
    };
  }
}

/** disablePush unsubscribes the browser and forgets it on the server. */
export async function disablePush(): Promise<void> {
  const id = storage()?.getItem(SUBSCRIPTION_KEY) ?? "";
  storage()?.removeItem(SUBSCRIPTION_KEY);
  try {
    const reg = await navigator.serviceWorker?.ready;
    const sub = await reg?.pushManager?.getSubscription();
    await sub?.unsubscribe();
  } catch {
    /* the browser may have dropped it already */
  }
  if (id && id !== "1") {
    try {
      await localFetch(`/coddy/push/subscriptions/${encodeURIComponent(id)}`, {
        method: "DELETE",
      });
    } catch {
      /* the server drops it on the push service's 410 anyway */
    }
  }
  emit();
}

/** sendTestPush asks the server for a test notice to this device. */
export async function sendTestPush(): Promise<number> {
  const res = await localFetch("/coddy/push/test", {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify({ device: deviceId() }),
  });
  if (!res.ok) {
    throw new Error(`test push: ${res.status}`);
  }
  const body = (await res.json()) as { sent?: number };
  return body.sent ?? 0;
}

/**
 * installPresence reports to the page's own server whether this tab has the
 * person's attention, so the server pushes only what nobody sees. It reports
 * on every change and once a minute while attentive. It answers the function
 * that stops it.
 */
export function installPresence(): () => void {
  if (typeof window === "undefined" || getEnv().mode !== "local") {
    return () => {};
  }
  let last: boolean | null = null;
  const report = (force: boolean, leaving = false) => {
    // A page that is going away has nobody's attention, whatever the
    // visibility still says at that moment; otherwise a closed tab would keep
    // the pushes quiet until its last report expires on the server.
    const attentive = leaving ? false : pageHasAttention();
    if (!force && attentive === last) {
      return;
    }
    last = attentive;
    void localFetch("/coddy/presence", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ device: deviceId(), attentive }),
      keepalive: true,
    }).catch(() => {
      /* a server without the route, or offline: nothing to report to */
    });
  };
  const onChange = () => report(false);
  const onLeave = () => report(false, true);
  document.addEventListener("visibilitychange", onChange);
  window.addEventListener("focus", onChange);
  window.addEventListener("blur", onChange);
  window.addEventListener("pagehide", onLeave);
  const timer = window.setInterval(() => {
    if (pageHasAttention()) report(true);
  }, PRESENCE_EVERY_MS);
  report(true);
  return () => {
    document.removeEventListener("visibilitychange", onChange);
    window.removeEventListener("focus", onChange);
    window.removeEventListener("blur", onChange);
    window.removeEventListener("pagehide", onLeave);
    window.clearInterval(timer);
  };
}
