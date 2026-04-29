/**
 * ThemeToggle behaviour:
 *   - active option carries the primary underline
 *   - clicking each option flips <html data-theme> and localStorage
 *   - aria attributes expose state to assistive tech
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";

import { ThemeProvider } from "../providers/ThemeProvider";
import { ThemeToggle } from "../explorer/ThemeToggle";
import { THEME_STORAGE_KEY } from "@/lib/theme";

function renderToggle() {
  return render(
    <ThemeProvider>
      <ThemeToggle />
    </ThemeProvider>,
  );
}

describe("ThemeToggle", () => {
  beforeEach(() => {
    window.localStorage.clear();
    document.documentElement.removeAttribute("data-theme");
  });

  afterEach(() => {
    window.localStorage.clear();
  });

  it("renders three options with role=radio", () => {
    renderToggle();
    expect(screen.getByTestId("theme-option-dark").getAttribute("role")).toBe(
      "radio",
    );
    expect(screen.getByTestId("theme-option-light").getAttribute("role")).toBe(
      "radio",
    );
    expect(screen.getByTestId("theme-option-system").getAttribute("role")).toBe(
      "radio",
    );
  });

  it("default mode is system; clicking dark updates html + localStorage", () => {
    renderToggle();
    expect(screen.getByTestId("theme-option-system").getAttribute("aria-checked")).toBe(
      "true",
    );

    fireEvent.click(screen.getByTestId("theme-option-dark"));
    expect(document.documentElement.getAttribute("data-theme")).toBe("dark");
    expect(window.localStorage.getItem(THEME_STORAGE_KEY)).toBe("dark");
    expect(screen.getByTestId("theme-option-dark").getAttribute("aria-checked")).toBe(
      "true",
    );
    expect(screen.getByTestId("theme-option-dark").className).toMatch(/border-primary/);
  });

  it("clicking light flips data-theme and stores 'light'", () => {
    renderToggle();
    fireEvent.click(screen.getByTestId("theme-option-light"));
    expect(document.documentElement.getAttribute("data-theme")).toBe("light");
    expect(window.localStorage.getItem(THEME_STORAGE_KEY)).toBe("light");
  });

  it("clicking system stores 'system' (resolved value depends on matchMedia)", () => {
    renderToggle();
    fireEvent.click(screen.getByTestId("theme-option-dark"));
    fireEvent.click(screen.getByTestId("theme-option-system"));
    expect(window.localStorage.getItem(THEME_STORAGE_KEY)).toBe("system");
    // jsdom's matchMedia is undefined or always false; the resolved attribute
    // must still be one of the two valid values.
    const painted = document.documentElement.getAttribute("data-theme");
    expect(painted === "dark" || painted === "light").toBe(true);
  });

  it("only the active option carries the primary underline", () => {
    renderToggle();
    fireEvent.click(screen.getByTestId("theme-option-light"));
    expect(screen.getByTestId("theme-option-light").className).toMatch(/border-primary/);
    expect(screen.getByTestId("theme-option-dark").className).not.toMatch(/border-primary/);
    expect(screen.getByTestId("theme-option-system").className).not.toMatch(/border-primary/);
  });
});
