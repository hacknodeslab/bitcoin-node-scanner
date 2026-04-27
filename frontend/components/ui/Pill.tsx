import { cn } from "@/lib/utils";

export type CveSeverity = "low" | "medium" | "high" | "critical";

export type PillKind =
  | { kind: "EXPOSED" }
  | { kind: "STALE" }
  | { kind: "TOR" }
  | { kind: "CVE"; severity: CveSeverity }
  | { kind: "OK" };

type Tone = "alert" | "warn" | "ok";

function toneFor(p: PillKind): Tone {
  switch (p.kind) {
    case "EXPOSED":
    case "STALE":
      return "alert";
    case "TOR":
      return "warn";
    case "CVE":
      return p.severity === "high" || p.severity === "critical" ? "alert" : "warn";
    case "OK":
      return "ok";
  }
}

const TONE_CLASSES: Record<Tone, string> = {
  alert: "text-alert bg-alert-bg",
  warn: "text-warn bg-warn-bg",
  ok: "text-ok bg-ok-bg",
};

export function Pill(props: PillKind & { className?: string }) {
  const tone = toneFor(props);
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
      {props.kind}
    </span>
  );
}
