"use client";

/**
 * Shared table pagination footer: prev/next, "Page X of Y · N <noun>", and a
 * rows-per-page select. Used by the explorer-style tables (vulnerabilities,
 * nostr). Page numbers are 1-based; the caller owns page/pageSize state.
 */
export interface PaginationProps {
  page: number;
  pageSize: number;
  total: number;
  /** Plural noun for the total, e.g. "CVEs" or "relays". */
  noun: string;
  /** Page-size options offered in the select. */
  pageSizes?: readonly number[];
  onPrev: () => void;
  onNext: () => void;
  onPageSizeChange: (size: number) => void;
}

const DEFAULT_PAGE_SIZES = [25, 50, 100] as const;

export function Pagination({
  page,
  pageSize,
  total,
  noun,
  pageSizes = DEFAULT_PAGE_SIZES,
  onPrev,
  onNext,
  onPageSizeChange,
}: PaginationProps) {
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  return (
    <div
      data-testid="pagination"
      className="flex items-center gap-[14px] px-[14px] py-[8px] border-t border-border text-meta text-muted"
    >
      <button
        type="button"
        onClick={onPrev}
        disabled={page <= 1}
        data-testid="pagination-prev"
        className="text-text-dim hover:text-text disabled:text-dim disabled:cursor-not-allowed cursor-pointer"
      >
        ‹ prev
      </button>
      <span data-testid="pagination-status">
        Page {page} of {totalPages} · {total} {noun}
      </span>
      <button
        type="button"
        onClick={onNext}
        disabled={page >= totalPages}
        data-testid="pagination-next"
        className="text-text-dim hover:text-text disabled:text-dim disabled:cursor-not-allowed cursor-pointer"
      >
        next ›
      </button>
      <span className="ml-auto flex items-center gap-[6px]">
        <span className="text-dim">rows</span>
        <select
          data-testid="pagination-page-size"
          value={pageSize}
          onChange={(e) => onPageSizeChange(Number(e.target.value))}
          className="bg-surface-2 text-text-dim border border-border px-[6px] py-[2px] text-meta cursor-pointer"
        >
          {pageSizes.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
      </span>
    </div>
  );
}
