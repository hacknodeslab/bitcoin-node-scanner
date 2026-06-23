import { cn } from "@/lib/utils";
import { NON_CDN_VERDICTS } from "@/lib/nostr";

export type CveSeverity = "low" | "medium" | "high" | "critical";

export type PillKind =
  | { kind: "EXPOSED" }
  | { kind: "STALE" }
  | { kind: "TOR" }
  | { kind: "CVE"; severity: CveSeverity }
  | { kind: "OK" }
  | { kind: "EXAMPLE" }
  | { kind: "DEV" }
  | { kind: "RISK"; severity: CveSeverity }
  | { kind: "BITCOIN" }
  | { kind: "CDN"; verdict: string }
  | { kind: "TAG"; label: string };

type Tone = "alert" | "warn" | "ok" | "accent" | "dim" | "primary";

function toneFor(p: PillKind): Tone {
  switch (p.kind) {
    case "EXPOSED":
    case "STALE":
      return "alert";
    case "TOR":
      return "warn";
    case "CVE":
    case "RISK":
      return p.severity === "high" || p.severity === "critical" ? "alert" : "warn";
    case "OK":
      return "ok";
    case "EXAMPLE":
      return "accent";
    case "DEV":
      return "warn";
    case "BITCOIN":
      return "primary";
    case "CDN": {
      const v = p.verdict.toLowerCase();
      // `direct` = origin visible (decentralized → ok); behind a CDN =
      // centralization concern (warn); unresolved/skipped = neutral.
      if (v === "direct") return "ok";
      if (NON_CDN_VERDICTS.has(v)) return "dim";
      return "warn";
    }
    case "TAG":
      return "dim";
  }
}

const TONE_CLASSES: Record<Tone, string> = {
  alert: "text-alert bg-alert-bg",
  warn: "text-warn bg-warn-bg",
  ok: "text-ok bg-ok-bg",
  accent: "text-accent bg-accent-bg",
  dim: "text-text-dim bg-surface-2",
  // Bitcoin orange chip with the design-system "on-primary" foreground.
  // Both `primary` and `on-primary` tokens are identical in dark and light
  // themes (#F7931A / #0a0a0a), so contrast (≈8.7:1) is the same on both.
  primary: "text-on-primary bg-primary",
};

export function Pill(props: PillKind & { className?: string }) {
  const tone = toneFor(props);
  const label =
    props.kind === "TAG"
      ? props.label.toUpperCase()
      : props.kind === "RISK"
        ? props.severity.toUpperCase()
        : props.kind === "CDN"
          ? props.verdict.replace(/_/g, " ").toUpperCase()
          : props.kind;
  return (
    <span
      data-pill-kind={props.kind}
      className={cn(
        "inline-block text-label uppercase tracking-[0.3px]",
        "px-[7px] py-[2px]",
        TONE_CLASSES[tone],
        props.className,
      )}
    >
      {label}
    </span>
  );
}
