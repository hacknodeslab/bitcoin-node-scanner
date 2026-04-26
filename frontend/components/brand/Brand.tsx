/**
 * Brand mark — `bns / scanner`. The slash and the leading `bns` use the
 * primary token; this is one of the three orange touchpoints permitted per
 * screen (the others are the QueryBar `›` prompt and the L402 button).
 */
export interface BrandProps {
  className?: string;
  /** When true, hide the descriptive subtitle (footer or compact contexts). */
  compact?: boolean;
}

export function Brand({ className, compact }: BrandProps) {
  return (
    <div className={className} data-testid="brand">
      <div className="text-title">
        <span className="text-primary">bns</span>
        <span className="text-dim"> / </span>
        <span className="text-text">scanner</span>
      </div>
      {compact ? null : (
        <div className="text-meta text-muted">bitcoin node security recon</div>
      )}
    </div>
  );
}
