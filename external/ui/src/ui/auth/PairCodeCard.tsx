import { useState, type FormEvent } from "react";
import { useT } from "../i18n/I18nProvider";
import { pairWithCode, snapshotAuth } from "./authState";

/**
 * PairCodeCard signs this browser in with the pairing code the computer shows
 * in Settings, Phone: the way into an open server reached under another name
 * than localhost, and the second way in next to the password. A phone usually
 * arrives through the QR code's link, which carries the code; on iPhone the
 * app added to the home screen keeps cookies of its own, so the person types
 * the same code there once.
 */
export function PairCodeCard(props: { compact?: boolean }) {
  const { t } = useT();
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(() =>
    snapshotAuth().pairRefused ? t("auth.pair.refused") : "",
  );

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    const res = await pairWithCode(code);
    setBusy(false);
    if (!res.ok) {
      setError(
        res.status === 401
          ? t("auth.pair.refused")
          : t("auth.pair.failed", { status: String(res.status) }),
      );
    }
  };

  return (
    <form
      className={
        props.compact
          ? "auth-card auth-pair auth-pair--compact"
          : "auth-card auth-pair"
      }
      onSubmit={(e) => void submit(e)}
      data-testid="pair-code-card"
    >
      <h1 className="auth-title">{t("auth.pair.title")}</h1>
      <p className="auth-copy">{t("auth.pair.copy")}</p>
      {error ? (
        <p className="auth-error" role="alert">
          {error}
        </p>
      ) : null}
      <label className="auth-field">
        <span className="auth-label">{t("auth.pair.code")}</span>
        <input
          className="auth-input auth-code-input"
          autoComplete="one-time-code"
          autoCapitalize="characters"
          spellCheck={false}
          inputMode="text"
          maxLength={9}
          placeholder="ABCD-EFGH"
          value={code}
          onChange={(e) => setCode(e.target.value.toUpperCase())}
          data-testid="pair-code-input"
        />
      </label>
      <button
        className="auth-submit"
        type="submit"
        disabled={busy || code.replace(/[^A-Za-z0-9]/g, "").length !== 8}
      >
        {busy ? t("auth.signIn.working") : t("auth.pair.submit")}
      </button>
    </form>
  );
}
