/**
 * QueryBarController owns a draft string and lifts it on Enter only.
 * The active-filters preview renders only the *applied* value, not the draft.
 */
import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { useState } from "react";

import { QueryBarController } from "../explorer/QueryBarController";

function Harness({ onApply }: { onApply: (q: string) => void }) {
  const [v, setV] = useState("");
  return (
    <QueryBarController
      value={v}
      onApply={(q) => {
        setV(q);
        onApply(q);
      }}
    />
  );
}

describe("QueryBarController", () => {
  it("Enter calls onApply with the typed draft", () => {
    const onApply = vi.fn();
    render(<Harness onApply={onApply} />);
    const input = screen.getByTestId("query-bar-input") as HTMLInputElement;
    fireEvent.change(input, { target: { value: "risk=critical" } });
    fireEvent.submit(input.closest("form")!);
    expect(onApply).toHaveBeenCalledWith("risk=critical");
  });

  it("draft typing alone does NOT call onApply", () => {
    const onApply = vi.fn();
    render(<Harness onApply={onApply} />);
    const input = screen.getByTestId("query-bar-input") as HTMLInputElement;
    fireEvent.change(input, { target: { value: "risk=critical" } });
    expect(onApply).not.toHaveBeenCalled();
  });

  it("syncs the draft when `value` changes externally", () => {
    function ControlledHarness({ value }: { value: string }) {
      return <QueryBarController value={value} onApply={() => {}} />;
    }
    const { rerender } = render(<ControlledHarness value="" />);
    const input = screen.getByTestId("query-bar-input") as HTMLInputElement;
    expect(input.value).toBe("");
    rerender(<ControlledHarness value="exposed=true" />);
    expect(input.value).toBe("exposed=true");
  });

  it("renders warnings when supplied", () => {
    render(
      <QueryBarController
        value="risk=neon"
        onApply={() => {}}
        warnings={["risk=neon: must be CRITICAL|HIGH|MEDIUM|LOW"]}
      />,
    );
    const w = screen.getByTestId("query-bar-warnings");
    expect(w.textContent).toContain("risk=neon");
  });

  it("active-filters preview appears only when value is non-empty", () => {
    const { container, rerender } = render(
      <QueryBarController value="" onApply={() => {}} />,
    );
    // QueryBar (display) renders the empty-state hint; we don't render it
    // when the applied value is empty.
    expect(container.textContent).not.toContain("type a key=value query");

    rerender(<QueryBarController value="risk=critical" onApply={() => {}} />);
    // The applied query renders the parsed chip; risk + = + critical text appears.
    expect(container.textContent).toContain("risk");
    expect(container.textContent).toContain("critical");
  });
});
