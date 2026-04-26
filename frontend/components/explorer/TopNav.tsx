import { Brand } from "@/components/brand/Brand";
import { Glyph } from "@/components/ui/Glyph";

/**
 * Top navigation strip: brand mark on the left, command-palette hint on the
 * right. The actual ⌘K listener and palette UI land in §9; here we render the
 * affordance only.
 */
export function TopNav() {
  return (
    <header
      className="flex items-center justify-between px-[14px] py-[10px] border-b border-border"
      data-testid="top-nav"
    >
      <Brand />
      <div className="flex items-center gap-[6px] text-meta text-muted">
        <Glyph name="cmd" />
        <span>K</span>
        <span className="text-dim">·</span>
        <span>palette</span>
      </div>
    </header>
  );
}
