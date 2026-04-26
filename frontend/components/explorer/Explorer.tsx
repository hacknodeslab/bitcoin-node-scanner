"use client";

import { useMemo, useState } from "react";
import { QueryBarController } from "./QueryBarController";
import { NodeTable } from "./NodeTable";
import { parseQueryToFilters } from "@/lib/query-grammar";

/**
 * Client-side root for the explorer. Owns the applied query string and
 * derives both the filter object passed to NodeTable and the warning lines
 * surfaced under the query bar. The page (server component) composes
 * Explorer alongside the static strips above and below it.
 */
export function Explorer() {
  const [appliedQuery, setAppliedQuery] = useState<string>("");

  const { filters, warnings } = useMemo(
    () => parseQueryToFilters(appliedQuery),
    [appliedQuery],
  );

  return (
    <>
      <QueryBarController
        value={appliedQuery}
        onApply={setAppliedQuery}
        warnings={warnings}
      />
      <NodeTable filters={filters} />
    </>
  );
}
