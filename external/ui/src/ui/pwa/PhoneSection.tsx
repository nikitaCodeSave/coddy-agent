import { useCallback, useEffect, useState, useSyncExternalStore } from "react";
import { useT } from "../i18n/I18nProvider";
import { localFetch } from "../env/remoteEnv";
import { SwitchField } from "../settings/SwitchField";
import { SETTINGS_TEXTS, landmarkAnchor } from "../settings/settingsSections";
import {
  disablePush,
  enablePush,
  pushStateSnapshot,
  sendTestPush,
  subscribePushState,
  type PushSupport,
} from "./push";

type Pairing = {
  code: string;
  url: string;
  qr_png: string;
  expiresAt: string;
  secure: boolean;
};

type Device = {
  id: string;
  name: string;
  createdAt: string;
  lastSeenAt: string;
  current: boolean;
};

const PUSH_STATUS_KEY: Partial<Record<PushSupport, string>> = {
  unsupported: "phone.push.unsupported",
  insecure: "phone.push.insecure",
  install: "phone.push.install",
  denied: "phone.push.denied",
  remote: "phone.push.remote",
};

function isLoopbackPage(): boolean {
  if (typeof window === "undefined") return true;
  const host = window.location.hostname;
  return (
    host === "localhost" ||
    host.endsWith(".localhost") ||
    host === "127.0.0.1" ||
    host === "::1" ||
    host === "[::1]"
  );
}

function formatDate(value: string): string {
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? value : d.toLocaleString();
}

/**
 * PushSetting is the switch of the notices that reach this device with Coddy
 * closed (Web Push), and the button that sends a test notice.
 */
export function PushSetting() {
  const { t } = useT();
  const snapshot = useSyncExternalStore(
    subscribePushState,
    pushStateSnapshot,
    () => "off:unsupported",
  );
  const [pref, support] = snapshot.split(":") as [string, PushSupport];
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState("");
  const on = pref === "on";

  const toggle = useCallback(
    async (next: boolean) => {
      setBusy(true);
      setNote("");
      try {
        if (next) {
          const res = await enablePush();
          if (!res.ok) setNote(t("phone.push.failed", { reason: res.reason }));
        } else {
          await disablePush();
        }
      } finally {
        setBusy(false);
      }
    },
    [t],
  );

  const test = useCallback(async () => {
    setBusy(true);
    try {
      const sent = await sendTestPush();
      setNote(sent > 0 ? t("phone.push.testSent") : t("phone.push.testNone"));
    } catch {
      setNote(t("phone.push.testNone"));
    } finally {
      setBusy(false);
    }
  }, [t]);

  const statusKey = PUSH_STATUS_KEY[support];
  return (
    <div className="phone-push" data-testid="phone-push">
      <SwitchField
        checked={on}
        onChange={(next) => void toggle(next)}
        label={t("phone.push.toggle")}
        description={t("phone.push.hint")}
        disabled={busy || (!on && support !== "ready")}
        dataTestId="phone-push-switch"
      />
      {statusKey ? (
        <p
          className="settings-field-desc"
          role="status"
          data-testid="phone-push-status"
        >
          {t(statusKey)}
        </p>
      ) : null}
      {on ? (
        <button
          type="button"
          className="settings-btn"
          onClick={() => void test()}
          disabled={busy}
          data-testid="phone-push-test"
        >
          {t("phone.push.test")}
        </button>
      ) : null}
      {note ? (
        <p
          className="settings-field-desc"
          role="status"
          data-testid="phone-push-note"
        >
          {note}
        </p>
      ) : null}
    </div>
  );
}

/**
 * PhoneSection is Settings → Phone: the QR code that pairs a phone, the
 * notices of this device, and the devices paired so far.
 */
export function PhoneSection() {
  const { t } = useT();
  const [base, setBase] = useState(() =>
    isLoopbackPage() ? "" : window.location.origin,
  );
  const [pairing, setPairing] = useState<Pairing | null>(null);
  const [devices, setDevices] = useState<Device[]>([]);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const loadDevices = useCallback(async () => {
    try {
      const res = await localFetch("/coddy/devices", {
        headers: { Accept: "application/json" },
      });
      if (res.ok) {
        const body = (await res.json()) as { data?: Device[] };
        setDevices(body.data ?? []);
      }
    } catch {
      /* the list stays as it was */
    }
  }, []);

  useEffect(() => {
    void loadDevices();
  }, [loadDevices]);

  const showCode = useCallback(async () => {
    setBusy(true);
    setError("");
    try {
      const res = await localFetch("/coddy/devices/pairing", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        body: JSON.stringify({ baseUrl: base.trim() }),
      });
      const body = (await res.json()) as Pairing & { error?: string };
      if (!res.ok) {
        setError(body.error || t("phone.pair.failed"));
        return;
      }
      setPairing(body);
    } catch {
      setError(t("phone.pair.failed"));
    } finally {
      setBusy(false);
    }
  }, [base, t]);

  const unpair = useCallback(
    async (id: string) => {
      await localFetch(`/coddy/devices/${encodeURIComponent(id)}`, {
        method: "DELETE",
      });
      await loadDevices();
    },
    [loadDevices],
  );

  const linkIsLocal = pairing
    ? /\/\/(localhost|127\.0\.0\.1|\[::1\])[:/]/.test(pairing.url)
    : false;

  return (
    <div className="phone-section" data-testid="phone-section">
      <fieldset
        className="settings-fieldset"
        data-settings-anchor={landmarkAnchor("phone", "pair")}
      >
        <legend>{t(SETTINGS_TEXTS.phonePair.label)}</legend>
        <p className="settings-field-desc">{t("phone.pair.intro")}</p>
        <div className="settings-row">
          <label className="settings-label" htmlFor="phone-base-url">
            {t("phone.pair.address")}
          </label>
          <input
            id="phone-base-url"
            className="settings-input"
            type="url"
            inputMode="url"
            placeholder="https://192.168.1.50"
            value={base}
            onChange={(e) => setBase(e.target.value)}
            data-testid="phone-base-url"
          />
          <span className="settings-field-desc">
            {t("phone.pair.addressHint")}
          </span>
        </div>
        <button
          type="button"
          className="settings-btn settings-btn-primary"
          onClick={() => void showCode()}
          disabled={busy}
          data-testid="phone-show-code"
        >
          {pairing ? t("phone.pair.again") : t("phone.pair.show")}
        </button>
        {error ? (
          <p className="settings-error" role="alert">
            {error}
          </p>
        ) : null}
        {pairing ? (
          <div className="auth-enrollment-grid" data-testid="phone-pairing">
            <div className="auth-enrollment-qr-column">
              <img
                className="auth-enrollment-qr"
                src={pairing.qr_png}
                alt={t("phone.pair.qrAlt")}
              />
              <span className="auth-enrollment-hint">
                {t("phone.pair.scan")}
              </span>
            </div>
            <div className="auth-enrollment-fields">
              <p className="settings-field-desc">{t("phone.pair.codeLabel")}</p>
              <p className="phone-pair-code" data-testid="phone-pair-code">
                {pairing.code}
              </p>
              <p className="settings-field-desc phone-pair-link">
                {pairing.url}
              </p>
              <p className="settings-field-desc">
                {t("phone.pair.expires", {
                  time: formatDate(pairing.expiresAt),
                })}
              </p>
              {linkIsLocal ? (
                <p className="settings-error" role="status">
                  {t("phone.pair.localWarning")}
                </p>
              ) : !pairing.secure ? (
                <p className="settings-error" role="status">
                  {t("phone.pair.insecureWarning")}
                </p>
              ) : null}
            </div>
          </div>
        ) : null}
      </fieldset>

      <fieldset
        className="settings-fieldset"
        data-settings-anchor={landmarkAnchor("phone", "push")}
      >
        <legend>{t(SETTINGS_TEXTS.phonePush.label)}</legend>
        <PushSetting />
      </fieldset>

      <fieldset
        className="settings-fieldset"
        data-settings-anchor={landmarkAnchor("phone", "devices")}
      >
        <legend>{t(SETTINGS_TEXTS.phoneDevices.label)}</legend>
        {devices.length === 0 ? (
          <p className="settings-muted">{t("phone.devices.none")}</p>
        ) : (
          <ul className="phone-devices" data-testid="phone-devices">
            {devices.map((d) => (
              <li key={d.id} className="phone-device">
                <span className="phone-device-name">
                  {d.name}
                  {d.current ? ` (${t("phone.devices.this")})` : ""}
                </span>
                <span className="settings-field-desc">
                  {t("phone.devices.seen", { time: formatDate(d.lastSeenAt) })}
                </span>
                <button
                  type="button"
                  className="settings-btn settings-btn-danger"
                  onClick={() => void unpair(d.id)}
                >
                  {t("phone.devices.remove")}
                </button>
              </li>
            ))}
          </ul>
        )}
      </fieldset>
    </div>
  );
}
