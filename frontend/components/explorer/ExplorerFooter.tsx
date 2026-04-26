import { Glyph } from "@/components/ui/Glyph";

/**
 * Explorer footer strip. Shows keyboard hints and reserves space for the
 * scan trigger (§8.5). Today the trigger is a static label so the layout is
 * stable; the active button + polling lands with `useScanJob`.
 */
export function ExplorerFooter() {
  return (
    <footer
      className="flex items-center gap-[14px] px-[14px] py-[8px] border-t border-border text-meta text-muted"
      data-testid="explorer-footer"
    >
      <span className="flex items-center gap-[4px]">
        <span className="text-dim">/</span>
        <span>focus query</span>
      </span>
      <Glyph name="sep" className="text-dim" />
      <span className="flex items-center gap-[4px]">
        <Glyph name="cmd" />
        <span>K</span>
        <span>palette</span>
      </span>
      <span className="ml-auto text-dim">scan trigger arrives in §8.5</span>
    </footer>
  );
}
