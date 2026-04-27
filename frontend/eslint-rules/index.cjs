/**
 * Local ESLint plugin enforcing /DESIGN.md hard rules at lint time.
 * See change `redesign-dashboard-design-system`, design.md D5/D6/D7.
 */
"use strict";

/** Walk a className string literal and report any forbidden Tailwind utility. */
function checkClassName(context, node, value) {
  if (typeof value !== "string") return;
  const tokens = value.split(/\s+/).filter(Boolean);
  for (const t of tokens) {
    // strip variants like "hover:rounded-md" → "rounded-md"
    const bare = t.replace(/^(?:[a-zA-Z0-9-]+:)+/, "");

    // rounded-*: only rounded-none allowed
    if (/^rounded(-|$)/.test(bare) && bare !== "rounded-none") {
      context.report({
        node,
        messageId: "noRounded",
        data: { token: t },
      });
    }
    // shadows
    if (/^shadow(-|$)/.test(bare)) {
      context.report({ node, messageId: "noShadow", data: { token: t } });
    }
    // blur
    if (/^blur(-|$)/.test(bare)) {
      context.report({ node, messageId: "noBlur", data: { token: t } });
    }
    // backdrop-*
    if (/^backdrop-/.test(bare)) {
      context.report({ node, messageId: "noBackdrop", data: { token: t } });
    }
    // gradients
    if (/^bg-gradient-/.test(bare) || /^from-/.test(bare) || /^to-/.test(bare) || /^via-/.test(bare)) {
      context.report({ node, messageId: "noGradient", data: { token: t } });
    }
  }
}

const noBannedClassnames = {
  meta: {
    type: "problem",
    docs: { description: "Ban Tailwind utilities forbidden by /DESIGN.md." },
    schema: [],
    messages: {
      noRounded: "`{{token}}` is forbidden — /DESIGN.md mandates `rounded-none` everywhere.",
      noShadow: "`{{token}}` is forbidden — /DESIGN.md bans shadows.",
      noBlur: "`{{token}}` is forbidden — /DESIGN.md bans blurs.",
      noBackdrop: "`{{token}}` is forbidden — /DESIGN.md bans backdrop filters.",
      noGradient: "`{{token}}` is forbidden — /DESIGN.md bans gradients.",
    },
  },
  create(context) {
    return {
      JSXAttribute(node) {
        if (node.name && node.name.name === "className") {
          if (node.value && node.value.type === "Literal") {
            checkClassName(context, node.value, node.value.value);
          } else if (
            node.value &&
            node.value.type === "JSXExpressionContainer" &&
            node.value.expression &&
            node.value.expression.type === "Literal"
          ) {
            checkClassName(context, node.value.expression, node.value.expression.value);
          } else if (
            node.value &&
            node.value.type === "JSXExpressionContainer" &&
            node.value.expression &&
            node.value.expression.type === "TemplateLiteral"
          ) {
            for (const q of node.value.expression.quasis) {
              checkClassName(context, q, q.value.cooked);
            }
          }
        }
      },
    };
  },
};

const noBannedImports = {
  meta: {
    type: "problem",
    docs: { description: "Ban icon libraries; ban non-JetBrains-Mono font sources." },
    schema: [],
    messages: {
      noIconLib: "`{{name}}` is forbidden — /DESIGN.md mandates the Unicode glyph set via the `Glyph` component.",
      noFontSource: "`{{name}}` is forbidden — only `next/font/google` with `JetBrains_Mono` is allowed.",
    },
  },
  create(context) {
    const ICON_LIBS = [
      /^lucide-react$/,
      /^@heroicons\//,
      /^react-icons(\/|$)/,
      /^@radix-ui\/react-icons$/,
      /^@tabler\/icons/,
    ];
    const FONT_SOURCES = [/^@fontsource\//, /^@fontsource-variable\//];

    function check(node, src) {
      if (typeof src !== "string") return;
      for (const re of ICON_LIBS) {
        if (re.test(src)) {
          context.report({ node, messageId: "noIconLib", data: { name: src } });
          return;
        }
      }
      for (const re of FONT_SOURCES) {
        if (re.test(src)) {
          context.report({ node, messageId: "noFontSource", data: { name: src } });
          return;
        }
      }
    }
    return {
      ImportDeclaration(node) {
        check(node.source, node.source.value);
      },
      ImportExpression(node) {
        if (node.source && node.source.type === "Literal") check(node.source, node.source.value);
      },
    };
  },
};

const onlyJetbrainsMonoFont = {
  meta: {
    type: "problem",
    docs: {
      description:
        "From `next/font/google`, only `JetBrains_Mono` may be imported (one typeface rule).",
    },
    schema: [],
    messages: {
      notJetbrains:
        "`{{name}}` from `next/font/google` is forbidden — only `JetBrains_Mono` is allowed.",
    },
  },
  create(context) {
    return {
      ImportDeclaration(node) {
        if (node.source.value !== "next/font/google") return;
        for (const spec of node.specifiers) {
          if (spec.type === "ImportSpecifier" && spec.imported.name !== "JetBrains_Mono") {
            context.report({
              node: spec,
              messageId: "notJetbrains",
              data: { name: spec.imported.name },
            });
          }
        }
      },
    };
  },
};

const noInlineColor = {
  meta: {
    type: "problem",
    docs: { description: "Ban inline `style={{ color: ... }}` and `style={{ backgroundColor: ... }}`." },
    schema: [],
    messages: {
      noInline:
        "Inline `style.{{prop}}` is forbidden. Use a token-derived utility (e.g. `text-alert`, `bg-surface`) or `var(--color-*)` for non-Tailwind code paths.",
    },
  },
  create(context) {
    return {
      JSXAttribute(node) {
        if (!node.name || node.name.name !== "style") return;
        if (
          !node.value ||
          node.value.type !== "JSXExpressionContainer" ||
          !node.value.expression ||
          node.value.expression.type !== "ObjectExpression"
        ) {
          return;
        }
        for (const prop of node.value.expression.properties) {
          if (prop.type !== "Property" || !prop.key) continue;
          const name = prop.key.name || prop.key.value;
          if (name === "color" || name === "backgroundColor" || name === "borderColor") {
            context.report({
              node: prop,
              messageId: "noInline",
              data: { prop: name },
            });
          }
        }
      },
    };
  },
};

// Files where /DESIGN.md legitimately uses Bitcoin orange (primary):
//   - brand mark
//   - L402 button (Button l402 variant)
//   - active tab indicator (Tabs)
//   - table row selection 2px left border (TableRow)
//   - command palette focused-item left border (CommandPalette)
//   - drawer sliver active row left border (Drawer)
//   - query bar `›` prompt (QueryBar)
// The "≤3 orange touchpoints per screen" rule is a runtime cap, enforced by
// the visual-regression test (task 4.8), not by this static rule.
const ALLOWED_PRIMARY_GLOB = [
  /\/components\/brand\//,
  /\/components\/ui\/Button\.tsx$/,
  /\/components\/ui\/Tabs\.tsx$/,
  /\/components\/ui\/TableRow\.tsx$/,
  /\/components\/ui\/CommandPalette\.tsx$/,
  /\/components\/ui\/Drawer\.tsx$/,
  /\/components\/ui\/QueryBar\.tsx$/,
];

const primaryAllowlist = {
  meta: {
    type: "problem",
    docs: {
      description:
        "Cap `text-primary` / `bg-primary` / `border-primary` usage to the design-system allow-list.",
    },
    schema: [],
    messages: {
      offAllowlist:
        "`{{token}}` (Bitcoin orange) used outside the allow-list (brand mark, Button l402 variant, Tabs focused indicator). /DESIGN.md caps decorative orange.",
    },
  },
  create(context) {
    const filename = context.getFilename().replace(/\\/g, "/");
    const allowed = ALLOWED_PRIMARY_GLOB.some((re) => re.test(filename));
    if (allowed) return {};

    function check(node, value) {
      if (typeof value !== "string") return;
      for (const t of value.split(/\s+/).filter(Boolean)) {
        const bare = t.replace(/^(?:[a-zA-Z0-9-]+:)+/, "");
        if (
          bare === "text-primary" ||
          bare === "bg-primary" ||
          bare === "border-primary"
        ) {
          context.report({ node, messageId: "offAllowlist", data: { token: t } });
        }
      }
    }

    return {
      JSXAttribute(node) {
        if (!node.name || node.name.name !== "className") return;
        if (node.value && node.value.type === "Literal") {
          check(node.value, node.value.value);
        } else if (
          node.value &&
          node.value.type === "JSXExpressionContainer" &&
          node.value.expression &&
          node.value.expression.type === "Literal"
        ) {
          check(node.value.expression, node.value.expression.value);
        }
      },
    };
  },
};

module.exports = {
  rules: {
    "no-banned-classnames": noBannedClassnames,
    "no-banned-imports": noBannedImports,
    "only-jetbrains-mono-font": onlyJetbrainsMonoFont,
    "no-inline-color": noInlineColor,
    "primary-allowlist": primaryAllowlist,
  },
};
