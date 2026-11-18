"""Self-contained HTML/CSS/JS for the icsScanner web UI — inline, no CDN dependencies (same
"no CDN deps" convention already stated for this project's HTML report output, core/reporter.py).
Two tabs: Scanner (the original scan-configuration form + run view, same two-step consent gate
confirm_destructive_run() enforces on the CLI) and Discovery (new — active ARP scan / passive
multi-protocol listener, with a "copy selected to Scanner" export into the inventory textarea).

Visual design, 2026-08-25 (frontend-design skill pass): deliberately diverges from
core/reporter.py's HTML report palette (blue accent, cool dark panels) rather than matching it.
The report is a document a user reads once, after the fact — a calm reading palette is right for
that. This page is the operator's live control instrument WHILE it fires real probe traffic at
live OT equipment — a different moment entirely. The palette here is drawn from the actual
instrumentation this tool talks to: protection-relay front panels (SEL/GE/ABB) use a red/amber/
green Trip/Alarm/Healthy lamp convention as their primary operator-facing status language — that
becomes this page's signature element (a 3-lamp cluster in the header, wired to real run state,
not decorative), and the rest of the page (hairline rules, sharp corners, mono-first type) stays
disciplined around it rather than competing with it.

Lamp state, 2026-09-02: a background heartbeat (startHeartbeat(), /api/health) drives HEALTHY/
TRIP at rest — green while this server process answers, red if it stops responding — the same
"is the panel itself alive" signal a real relay's healthy lamp gives. It never overrides an
in-flight scan/discovery job's own AMBER/TRIP/HEALTHY result (gated by the jobRunning flag), so a
confirmed finding's red TRIP lamp can't get silently clobbered back to green by the next
heartbeat tick.

Palette refresh, 2026-09-12 (user: sample bishopfox.com's palette/style without copying it, and
sharpen the industrial theme): fetched the live site's actual served CSS (not guessed) and pulled
its real neutral family (near-black grounds, graphite grays) as a reference point for this page's
own neutrals — every hex actually used here is our own, shifted from theirs, not lifted. The
neutrals moved from the old warm olive-brass cast (--ground was #0b0c09) to a cooler graphite/
gunmetal one closer to Bishop Fox's own near-blacks.

Corrected same day, after the user supplied a real Bishop Fox page excerpt directly (a stat
callout, bold cyan-teal numerals on black): the first pass over-weighted a magenta swatch also
present in their CSS as "the" brand accent. --teal is the real signature color, not magenta — the
page's one accent color now does that job (bumped from a muted #14c8ae to a punchier #12dbc6,
still our own value, not their literal #00cdc5/#00ffc8) for links and the nameplate's small
square "asset tag" mark; the earlier --brand/--brand-dim tokens are retired rather than left as a
second, competing accent. Red/amber/green keep their existing warning-lamp meaning untouched.

Also added, same correction pass, after the user supplied a HUD/tactical-interface reference
image: teal corner brackets on the nameplate header, echoing that reference's own reticle-corner
frame — the page's second deliberate visual moment alongside the warning-notice's hazard-stripe
cap (amber/black repeating diagonal, real equipment-tagging/safety-signage language). Contrast-
checked (WCAG formula, computed directly): body text 15.7:1, teal link/accent 11.3:1 (both vs.
ground and vs. panel), muted labels 5.4-6.0:1, nameplate title 11.9:1, button/warning-box text
10+:1, all clear AA comfortably.

Panel-hardware pass, 2026-09-12 (user annotated a live screenshot directly: enlarge the
HEALTHY/ACTIVE/TRIP lamps and give them a real indicator-lens look; turn Run Scan into a large
round pushbutton): the 3 status lamps grew from an 11px flat dot to a 24px lens (radial-gradient
fill + a thick bezel-ring border + a brighter off-center highlight when lit) — same
green/amber/red meaning, just styled like a real panel-mount indicator instead of a CSS circle.
#run-btn (Run Scan only, not every button on the page — this is the one physical "press to
activate" control here) became a 104px round pushbutton: radial-gradient amber cap, a raised
drop-shadow "ledge" that flattens and glows on :active to read as a real press, and its own
disabled-state graphite recolor rather than the shared flat `opacity: 0.45` fade every other
button uses.

Brand palette upgraded to source, 2026-09-17: Bishop Fox supplied their own official
"icsScanner (Nebula-style)" stylesheet directly — an authoritative source, not a sampled/
approximated one like the 2026-09-12 pass above. Reaffirms (doesn't contradict) that pass's own
finding: their file's dominant "positive/link" accent is still teal/cyan (their token is named
`--foam`, #22b8ae) — magenta (`--bf-magenta`, #BF1363) appears in exactly one narrow role in
their file (an active-tab underline), not as "the" brand accent. Scope of this pass, per the
same-day discussion: a token-value swap only — --ground/--panel/--panel-in/--hairline/--text/
--muted/--paper now use their real values (--paper folded into --text: no BF equivalent for the
old invented brass tone), --teal/--teal-dim now use their real foam/foam-soft values, --mono/
--sans now load the real self-hosted IBM Plex Mono / Inter font files (no CDN dependency, per
this file's own "no CDN deps" rule) instead of system-font stacks. Did NOT touch: amber/red/
green lamp semantics, the run/discover/confirm pushbuttons' shape or interaction, the tab
switcher's structure, or the Laptop density mode — explicitly kept for the page's existing ICS
instrument feel; Bishop Fox's ask here was about brand color/type fidelity, not a redesign.
Contrast re-verified (WCAG formula, computed directly) against the new values: body text
16.76:1 (vs ground) / 15.71:1 (vs panel), muted labels 6.92:1 / 6.49:1, teal/foam accent 8.03:1 /
7.53:1 — all still clear AA comfortably.

Full mockup adopted, 2026-09-17, same day: Bishop Fox marketing supplied a complete matching HTML
mockup (not just the CSS) covering all 4 real tabs with real content (real check IDs, real
credential entries, the actual safety-notice copy). Per discussion, superseded the token-swap-only
scope above for the elements the earlier pass explicitly protected: the .nameplate/.lamp-cluster
header became .topbar/.light-system (same HEALTHY/ACTIVE/ERROR semantics, same setLamps()-driven
state, real Bishop Fox bulb styling instead of the bezel-lens design); the "Laptop View" text
button became a real .laptop-pill switch (same applyDensity()/toggleDensity(), same localStorage
key); the amber bezel pushbuttons (#run-btn/#discover-btn/#confirm-run-btn) became Bishop Fox's
smaller icon-only .cta buttons with an external caption pill (their mockup only shows the routine
case — Confirm and Run's own red-ring color variant was added here to keep this page's existing
destructive/adverse-gated-action distinction visible, since dropping it would lose a real safety
signal their static mockup never had to represent). Also adopted: .warn-strip/.notice-light for
the top/bottom warning notices (deliberately drops the earlier hazard-stripe cap in favor of their
plain-card treatment), .card corner-rivet dots on every .panel, .badge-style pills for the
adverse/destructive tags (colors kept as this project's own red/amber risk convention, not
repainted to Bishop Fox's own badge hex values, to avoid colliding with the ERROR bulb's meaning),
.cred-card for the Credentials tab (replacing generic .panel there), .search-bar icon prefixes,
.empty-state boxes, and the real embedded Bishop Fox logo (extracted from their mockup's inline
base64 PNG to web/static/bishopfox-logo.png, served via the existing /static/ route) in place of
the earlier "text-only branding" placeholder decision. The vendor-hint text filter added earlier
this same session (after Bishop Fox's original CSS snapshot, so their mockup naturally predates
and doesn't show it) was kept and just inherits the new input styling -- flagged explicitly by the
user mid-rebuild as something not to lose.

Vendor filter promoted to its own checklist box, 2026-09-17 (user sketched a 3rd column matching
Protocols' exact size/shape): replaced the free-text `#vendor-filter` input with a genuine
checkbox multiselect (`#vendor-list`, `.vendor-cb`), matching `#protocol-list`/`.proto-cb`
structurally and combined via the same AND-filter logic in applyCheckFilters(). Flagged this
choice honestly before building it: 68 distinct vendors vs. 15 protocols (computed directly from
the loaded registry) means this list scrolls much more than Protocols' does, and a free-text
filter is normally the better fit for a set that large -- the user chose the exact-parity layout
anyway, so this is a deliberate, informed tradeoff (visual/interaction consistency with
Protocols), not an oversight.
"""

INDEX_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>icsScanner</title>
<style>
  /* Palette note, 2026-09-17: neutrals + --teal now use Bishop Fox's own real, officially
     supplied values (their "icsScanner Nebula-style" stylesheet), not a sampled approximation.
     --teal plays a small, deliberate role: link color, the nameplate's asset-tag mark, and its
     corner-bracket frame — never a status color. amber/red/green keep their existing
     warning-lamp meaning untouched (unrelated to Bishop Fox branding — these come from real
     protection-relay Trip/Alarm/Healthy convention, see this file's module docstring). */
  @font-face {
    font-family: 'Inter';
    font-style: normal;
    font-weight: 400 700;
    font-display: swap;
    src: url('/static/fonts/Inter-Variable.woff2') format('woff2');
  }
  @font-face {
    font-family: 'IBM Plex Mono';
    font-style: normal;
    font-weight: 400;
    font-display: swap;
    src: url('/static/fonts/IBMPlexMono-400.woff2') format('woff2');
  }
  @font-face {
    font-family: 'IBM Plex Mono';
    font-style: normal;
    font-weight: 500;
    font-display: swap;
    src: url('/static/fonts/IBMPlexMono-500.woff2') format('woff2');
  }
  @font-face {
    font-family: 'IBM Plex Mono';
    font-style: normal;
    font-weight: 600;
    font-display: swap;
    src: url('/static/fonts/IBMPlexMono-600.woff2') format('woff2');
  }
  :root {
    --ground:    #0a0a0e;
    --panel:     #131318;
    --panel-in:  #0c0c10;
    --hairline:  rgba(255,255,255,0.14);
    --text:      #ececef;
    --muted:     #9898a3;
    --paper:     #ececef;
    --amber:     #ffb020;
    --amber-dim: #4a3510;
    --red:       #ff3b30;
    --red-dim:   #4a1714;
    --green:     #34c759;
    --green-dim: #163a22;
    --teal:      #22b8ae;
    --teal-dim:  rgba(34,184,174,0.12);
    /* Added 2026-09-17, adopting Bishop Fox marketing's own icsScanner mockup wholesale (topbar
       light-system, laptop-pill, play-icon CTA) -- their real values, not our own shifted ones,
       since these come straight from their supplied HTML/CSS this time. */
    --bf-accent:      #ef4a5e;
    --bf-accent-soft: rgba(239, 74, 94, 0.12);
    --bf-accent-border: rgba(239, 74, 94, 0.4);
    --bf-magenta:      #BF1363;
    --bf-magenta-soft: rgba(191, 19, 99, 0.14);
    --bf-sunset:      #f0a23e;
    --bf-sunset-soft: rgba(240, 162, 62, 0.14);
    --bf-badge-amber:      #d99a3f;
    --bf-badge-amber-soft: rgba(217, 154, 63, 0.12);
    --bf-border:        rgba(255,255,255,0.08);
    --bf-border-strong: rgba(255,255,255,0.14);
    --bf-bg-card-2: #17171d;
    --bf-bg-code:   #0c0c10;
    --bf-radius:    8px;
    --bf-radius-sm: 5px;
    --mono: 'IBM Plex Mono', ui-monospace, "Cascadia Code", "SF Mono", Consolas, "Liberation Mono", monospace;
    --sans: 'Inter', -apple-system, "Segoe UI", Roboto, sans-serif;
  }
  * { box-sizing: border-box; }
  html { font-size: 16px; }
  body {
    background-color: var(--ground); color: var(--text); font-family: var(--mono);
    max-width: 1400px; margin: 0 auto; padding: 20px 16px 64px; font-size: 0.875rem;
    /* Circuit-board texture, straight from Bishop Fox's own supplied stylesheet — a real
       signature element of their "Nebula" theme, and a fitting one for an ICS/OT tool. */
    background-image: url("data:image/svg+xml,%3Csvg%20xmlns%3D%22http%3A//www.w3.org/2000/svg%22%20width%3D%22240%22%20height%3D%22240%22%3E%3Crect%20x%3D%220%22%20y%3D%2218%22%20width%3D%22240%22%20height%3D%223%22%20fill%3D%22rgba%28255%2C255%2C255%2C0.035%29%22/%3E%3Cg%20stroke%3D%22rgba%28255%2C255%2C255%2C0.05%29%22%20stroke-width%3D%221%22%3E%3Cline%20x1%3D%2210%22%20y1%3D%2214%22%20x2%3D%2210%22%20y2%3D%2224%22/%3E%3Cline%20x1%3D%2226%22%20y1%3D%2214%22%20x2%3D%2226%22%20y2%3D%2224%22/%3E%3Cline%20x1%3D%2242%22%20y1%3D%2214%22%20x2%3D%2242%22%20y2%3D%2224%22/%3E%3Cline%20x1%3D%2258%22%20y1%3D%2214%22%20x2%3D%2258%22%20y2%3D%2224%22/%3E%3Cline%20x1%3D%2274%22%20y1%3D%2214%22%20x2%3D%2274%22%20y2%3D%2224%22/%3E%3Cline%20x1%3D%2290%22%20y1%3D%2214%22%20x2%3D%2290%22%20y2%3D%2224%22/%3E%3Cline%20x1%3D%22106%22%20y1%3D%2214%22%20x2%3D%22106%22%20y2%3D%2224%22/%3E%3Cline%20x1%3D%22122%22%20y1%3D%2214%22%20x2%3D%22122%22%20y2%3D%2224%22/%3E%3Cline%20x1%3D%22138%22%20y1%3D%2214%22%20x2%3D%22138%22%20y2%3D%2224%22/%3E%3Cline%20x1%3D%22154%22%20y1%3D%2214%22%20x2%3D%22154%22%20y2%3D%2224%22/%3E%3Cline%20x1%3D%22170%22%20y1%3D%2214%22%20x2%3D%22170%22%20y2%3D%2224%22/%3E%3Cline%20x1%3D%22186%22%20y1%3D%2214%22%20x2%3D%22186%22%20y2%3D%2224%22/%3E%3Cline%20x1%3D%22202%22%20y1%3D%2214%22%20x2%3D%22202%22%20y2%3D%2224%22/%3E%3Cline%20x1%3D%22218%22%20y1%3D%2214%22%20x2%3D%22218%22%20y2%3D%2224%22/%3E%3Cline%20x1%3D%22234%22%20y1%3D%2214%22%20x2%3D%22234%22%20y2%3D%2224%22/%3E%3C/g%3E%3Cg%20fill%3D%22none%22%20stroke%3D%22rgba%28255%2C255%2C255%2C0.045%29%22%20stroke-width%3D%221%22%3E%3Crect%20x%3D%2214%22%20y%3D%2234%22%20width%3D%2210%22%20height%3D%2218%22%20rx%3D%221%22/%3E%3Crect%20x%3D%2234%22%20y%3D%2234%22%20width%3D%2210%22%20height%3D%2218%22%20rx%3D%221%22/%3E%3Crect%20x%3D%2254%22%20y%3D%2234%22%20width%3D%2210%22%20height%3D%2218%22%20rx%3D%221%22/%3E%3Crect%20x%3D%2274%22%20y%3D%2234%22%20width%3D%2210%22%20height%3D%2218%22%20rx%3D%221%22/%3E%3Crect%20x%3D%2294%22%20y%3D%2234%22%20width%3D%2210%22%20height%3D%2218%22%20rx%3D%221%22/%3E%3Crect%20x%3D%22114%22%20y%3D%2234%22%20width%3D%2210%22%20height%3D%2218%22%20rx%3D%221%22/%3E%3Crect%20x%3D%22134%22%20y%3D%2234%22%20width%3D%2210%22%20height%3D%2218%22%20rx%3D%221%22/%3E%3Crect%20x%3D%22154%22%20y%3D%2234%22%20width%3D%2210%22%20height%3D%2218%22%20rx%3D%221%22/%3E%3Crect%20x%3D%22174%22%20y%3D%2234%22%20width%3D%2210%22%20height%3D%2218%22%20rx%3D%221%22/%3E%3Crect%20x%3D%22194%22%20y%3D%2234%22%20width%3D%2210%22%20height%3D%2218%22%20rx%3D%221%22/%3E%3Crect%20x%3D%22214%22%20y%3D%2234%22%20width%3D%2210%22%20height%3D%2218%22%20rx%3D%221%22/%3E%3C/g%3E%3Crect%20x%3D%220%22%20y%3D%22158%22%20width%3D%22240%22%20height%3D%223%22%20fill%3D%22rgba%28255%2C255%2C255%2C0.035%29%22/%3E%3Cg%20stroke%3D%22rgba%28255%2C255%2C255%2C0.05%29%22%20stroke-width%3D%221%22%3E%3Cline%20x1%3D%2210%22%20y1%3D%22154%22%20x2%3D%2210%22%20y2%3D%22164%22/%3E%3Cline%20x1%3D%2226%22%20y1%3D%22154%22%20x2%3D%2226%22%20y2%3D%22164%22/%3E%3Cline%20x1%3D%2242%22%20y1%3D%22154%22%20x2%3D%2242%22%20y2%3D%22164%22/%3E%3Cline%20x1%3D%2258%22%20y1%3D%22154%22%20x2%3D%2258%22%20y2%3D%22164%22/%3E%3Cline%20x1%3D%2274%22%20y1%3D%22154%22%20x2%3D%2274%22%20y2%3D%22164%22/%3E%3Cline%20x1%3D%2290%22%20y1%3D%22154%22%20x2%3D%2290%22%20y2%3D%22164%22/%3E%3Cline%20x1%3D%22106%22%20y1%3D%22154%22%20x2%3D%22106%22%20y2%3D%22164%22/%3E%3Cline%20x1%3D%22122%22%20y1%3D%22154%22%20x2%3D%22122%22%20y2%3D%22164%22/%3E%3Cline%20x1%3D%22138%22%20y1%3D%22154%22%20x2%3D%22138%22%20y2%3D%22164%22/%3E%3Cline%20x1%3D%22154%22%20y1%3D%22154%22%20x2%3D%22154%22%20y2%3D%22164%22/%3E%3Cline%20x1%3D%22170%22%20y1%3D%22154%22%20x2%3D%22170%22%20y2%3D%22164%22/%3E%3Cline%20x1%3D%22186%22%20y1%3D%22154%22%20x2%3D%22186%22%20y2%3D%22164%22/%3E%3Cline%20x1%3D%22202%22%20y1%3D%22154%22%20x2%3D%22202%22%20y2%3D%22164%22/%3E%3Cline%20x1%3D%22218%22%20y1%3D%22154%22%20x2%3D%22218%22%20y2%3D%22164%22/%3E%3Cline%20x1%3D%22234%22%20y1%3D%22154%22%20x2%3D%22234%22%20y2%3D%22164%22/%3E%3C/g%3E%3Cg%20fill%3D%22none%22%20stroke%3D%22rgba%28255%2C255%2C255%2C0.045%29%22%20stroke-width%3D%221%22%3E%3Crect%20x%3D%2214%22%20y%3D%22174%22%20width%3D%2210%22%20height%3D%2218%22%20rx%3D%221%22/%3E%3Crect%20x%3D%2234%22%20y%3D%22174%22%20width%3D%2210%22%20height%3D%2218%22%20rx%3D%221%22/%3E%3Crect%20x%3D%2254%22%20y%3D%22174%22%20width%3D%2210%22%20height%3D%2218%22%20rx%3D%221%22/%3E%3Crect%20x%3D%2274%22%20y%3D%22174%22%20width%3D%2210%22%20height%3D%2218%22%20rx%3D%221%22/%3E%3Crect%20x%3D%2294%22%20y%3D%22174%22%20width%3D%2210%22%20height%3D%2218%22%20rx%3D%221%22/%3E%3Crect%20x%3D%22114%22%20y%3D%22174%22%20width%3D%2210%22%20height%3D%2218%22%20rx%3D%221%22/%3E%3Crect%20x%3D%22134%22%20y%3D%22174%22%20width%3D%2210%22%20height%3D%2218%22%20rx%3D%221%22/%3E%3Crect%20x%3D%22154%22%20y%3D%22174%22%20width%3D%2210%22%20height%3D%2218%22%20rx%3D%221%22/%3E%3Crect%20x%3D%22174%22%20y%3D%22174%22%20width%3D%2210%22%20height%3D%2218%22%20rx%3D%221%22/%3E%3Crect%20x%3D%22194%22%20y%3D%22174%22%20width%3D%2210%22%20height%3D%2218%22%20rx%3D%221%22/%3E%3Crect%20x%3D%22214%22%20y%3D%22174%22%20width%3D%2210%22%20height%3D%2218%22%20rx%3D%221%22/%3E%3C/g%3E%3Cline%20x1%3D%220%22%20y1%3D%2290%22%20x2%3D%22240%22%20y2%3D%2290%22%20stroke%3D%22rgba%28255%2C255%2C255%2C0.02%29%22%20stroke-width%3D%221%22%20stroke-dasharray%3D%221%205%22/%3E%3Cline%20x1%3D%220%22%20y1%3D%22120%22%20x2%3D%22240%22%20y2%3D%22120%22%20stroke%3D%22rgba%28255%2C255%2C255%2C0.02%29%22%20stroke-width%3D%221%22%20stroke-dasharray%3D%221%205%22/%3E%3C/svg%3E");
    background-repeat: repeat;
    background-size: 240px 240px;
  }

  /* ── Laptop density option, 2026-08-26 ────────────────────────────────
     Every font-size in this file is already rem-based, so bumping the root
     font-size scales all text proportionally with zero per-selector edits.
     Gutters (px-based padding/gaps) are trimmed separately in this same
     block. Off by default — a deliberate opt-in, not a redesign, since the
     base spacing/type scale was a considered choice (see this file's own
     module docstring), not an oversight to just globally override. */
  html[data-density="laptop"] { font-size: 18px; }
  [data-density="laptop"] body { padding: 12px 10px 40px; }
  [data-density="laptop"] header.topbar { height: 46px; padding: 0 14px; }
  [data-density="laptop"] .warn-strip { padding: 7px 14px; }
  [data-density="laptop"] .panel { padding: 11px; margin-bottom: 10px; }
  [data-density="laptop"] .row { gap: 10px; }
  [data-density="laptop"] .view { margin-top: 10px; }
  [data-density="laptop"] #confirm-box { padding: 10px 12px; margin-top: 10px; }
  [data-density="laptop"] .checklist { padding: 6px; max-height: 220px; }
  [data-density="laptop"] .notice-light { padding: 14px 16px; margin-top: 14px; }
  ::selection { background: var(--amber); color: #1a1200; }
  a { color: var(--teal); }
  a:focus-visible, button:focus-visible, input:focus-visible, textarea:focus-visible {
    outline: 2px solid var(--amber); outline-offset: 1px;
  }
  ::-webkit-scrollbar { width: 10px; height: 10px; }
  ::-webkit-scrollbar-track { background: var(--panel-in); }
  ::-webkit-scrollbar-thumb { background: var(--hairline); border-radius: 2px; }
  ::-webkit-scrollbar-thumb:hover { background: var(--muted); }

  /* ── Topbar, 2026-09-17: adopted wholesale from Bishop Fox marketing's own icsScanner mockup
     (replaces the earlier bespoke .nameplate/.lamp-cluster design) ──────────────────────── */
  header.topbar {
    height: 56px; display: flex; align-items: center; justify-content: space-between;
    padding: 0 24px; background: var(--panel-in); border-bottom: 1px solid var(--hairline);
    position: sticky; top: 0; z-index: 20;
  }
  .topbar-left { display: flex; align-items: center; gap: 16px; }
  .logo { display: flex; align-items: center; gap: 9px; }
  .logo-img { height: 18px; width: auto; display: block; }
  .topbar-divider { width: 1px; height: 22px; background: var(--hairline); }
  .app-label { display: flex; flex-direction: column; justify-content: center; padding: 2px 8px; }
  .app-label .app-title { font-size: 0.86rem; font-weight: 600; color: var(--text); line-height: 1.2; }
  .app-label .app-subtitle { font-size: 0.6rem; font-weight: 600; letter-spacing: 0.1em; color: var(--muted); margin-top: 2px; text-transform: uppercase; }
  .topbar-right { display: flex; align-items: center; gap: 20px; }

  /* Light system: same HEALTHY/ACTIVE/ERROR signal this page has always driven off real run
     state (see setLamps() / startHeartbeat()) — Bishop Fox's own bulb styling, not the earlier
     bezel-lens design. */
  .light-system { display: flex; align-items: center; gap: 16px; }
  .light-item { display: flex; flex-direction: column; align-items: center; gap: 6px; }
  .light-item .label { font-size: 0.58rem; font-weight: 700; letter-spacing: 0.09em; color: var(--muted); }
  .bulb {
    width: 12px; height: 12px; border-radius: 50%;
    background: radial-gradient(circle at 35% 30%, rgba(255,255,255,0.15), rgba(0,0,0,0.4) 80%);
    border: 1.5px solid #3a3a42;
    box-shadow: 0 0 0 2px var(--ground), 0 1px 1px rgba(0,0,0,0.6) inset;
  }
  .bulb.lit-healthy { background: radial-gradient(circle at 35% 30%, #bdf5f0, var(--teal) 70%); border-color: #0d5b56; box-shadow: 0 0 0 2px var(--ground), 0 0 8px var(--teal), 0 0 2px var(--teal); }
  .bulb.lit-active { background: radial-gradient(circle at 35% 30%, #ffe3b8, var(--bf-sunset) 70%); border-color: #8a5b1d; box-shadow: 0 0 0 2px var(--ground), 0 0 8px var(--bf-sunset), 0 0 2px var(--bf-sunset); animation: bulb-pulse 1.4s ease-in-out infinite; }
  .bulb.lit-error { background: radial-gradient(circle at 35% 30%, #ffc2cb, var(--bf-accent) 70%); border-color: #7a1622; box-shadow: 0 0 0 2px var(--ground), 0 0 8px var(--bf-accent), 0 0 2px var(--bf-accent); }
  @keyframes bulb-pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.45; } }
  @media (prefers-reduced-motion: reduce) { .bulb.lit-active { animation: none; } }

  /* Laptop density toggle, restyled as Bishop Fox's own pill switch (same feature/behavior as
     before — applyDensity()/toggleDensity() — just a real switch nub instead of plain text). */
  .laptop-pill {
    font-family: var(--sans); font-size: 0.6rem; letter-spacing: 0.08em; font-weight: 600;
    color: var(--muted); border: 1px solid var(--hairline); padding: 5px 10px; border-radius: 999px;
    background: var(--panel); white-space: nowrap; cursor: pointer; display: inline-flex;
    align-items: center; gap: 7px; transition: color 0.12s ease, border-color 0.12s ease, background 0.12s ease;
  }
  .laptop-pill:hover { color: var(--text); border-color: var(--muted); }
  .laptop-pill .switch {
    width: 20px; height: 11px; border-radius: 999px; background: #2a2830;
    border: 1px solid var(--hairline); position: relative; flex-shrink: 0;
    transition: background 0.15s ease, border-color 0.15s ease;
  }
  .laptop-pill .switch::after {
    content: ""; position: absolute; top: 1px; left: 1px; width: 7px; height: 7px; border-radius: 50%;
    background: var(--muted); transition: transform 0.15s ease, background 0.15s ease;
  }
  .laptop-pill.on { color: var(--text); border-color: var(--teal); }
  .laptop-pill.on .switch { background: var(--teal-dim); border-color: var(--teal); }
  .laptop-pill.on .switch::after { transform: translateX(9px); background: var(--teal); }

  /* ── Warning strip (top, compact) + notice-light (bottom, full) — 2026-09-17, adopted
     wholesale from Bishop Fox's mockup. Drops the earlier bespoke hazard-stripe cap in favor
     of their own plain-card + icon treatment (a deliberate call, made explicitly, not an
     oversight: see this file's module docstring). */
  .warn-strip {
    display: flex; align-items: center; gap: 10px; padding: 11px 24px;
    background: var(--panel-in); border-bottom: 1px solid var(--hairline);
    font-size: 0.83rem; color: var(--muted); font-family: var(--sans);
  }
  .warn-strip svg { width: 16px; height: 16px; flex-shrink: 0; color: var(--muted); }
  .warn-strip strong { color: var(--text); }
  .warn-strip a { color: var(--teal); text-decoration: none; }
  .warn-strip a:hover { text-decoration: underline; }

  .notice-light {
    background: var(--panel); color: var(--text); border: 1px solid var(--hairline);
    border-radius: var(--bf-radius); padding: 24px 28px; margin-top: 30px; font-family: var(--sans);
  }
  .notice-light .notice-head { display: flex; align-items: center; gap: 10px; margin-bottom: 14px; }
  .notice-light .notice-head svg { width: 18px; height: 18px; color: var(--muted); flex-shrink: 0; }
  .notice-light .notice-head h2 { font-size: 0.95rem; font-weight: 700; margin: 0; letter-spacing: 0.01em; color: var(--text); }
  .notice-light p { margin: 0 0 12px; font-size: 0.85rem; line-height: 1.6; color: var(--muted); }
  .notice-light p:last-child { margin-bottom: 0; }
  .notice-light strong { color: var(--text); }
  .notice-light code {
    font-family: var(--mono); background: var(--bf-bg-code); border: 1px solid var(--hairline);
    padding: 1px 5px; border-radius: 4px; color: var(--teal); font-size: 0.82em;
  }
  .notice-light a { color: var(--teal); text-decoration: none; }
  .notice-light a:hover { text-decoration: underline; }
  .notice-light ul { margin: 0 0 12px; padding-left: 20px; }
  .notice-light li { font-size: 0.85rem; line-height: 1.6; color: var(--muted); margin-bottom: 6px; }
  details.notice-light > summary.notice-head { cursor: pointer; margin-bottom: 0; list-style: none; }
  details.notice-light > summary.notice-head::-webkit-details-marker { display: none; }
  details.notice-light[open] > summary.notice-head { margin-bottom: 14px; }
  .notice-light .notice-head svg.notice-chevron { width: 16px; height: 16px; margin-left: auto; transition: transform 0.15s ease; }
  details.notice-light[open] > summary.notice-head svg.notice-chevron { transform: rotate(180deg); }
  .footer-links { text-align: center; margin: 0 0 20px; font-size: 0.75rem; letter-spacing: 0.04em; }
  .footer-links a { color: var(--teal); text-decoration: none; }
  .footer-links a:hover { text-decoration: underline; }

  /* ── Tabs, restyled to Bishop Fox's underline-tab treatment (same #tab-*-btn IDs/JS) ──── */
  .tab-switch { display: flex; padding: 0 4px; background: var(--panel-in); border-bottom: 1px solid var(--hairline); overflow-x: auto; }
  .tab-btn {
    background: none; color: var(--muted); border: none; border-bottom: 2px solid transparent;
    font-family: var(--sans); font-size: 0.83rem; font-weight: 600; padding: 15px 18px;
    cursor: pointer; white-space: nowrap; transition: color 0.15s ease, border-color 0.15s ease;
  }
  .tab-btn:hover { color: var(--text); }
  .tab-btn.active { background: none; color: var(--text); box-shadow: none; border-bottom-color: var(--bf-magenta); }
  .view { display: none; margin-top: 14px; }
  .view.active { display: block; }

  h3 { font-size: 0.82rem; margin: 0 0 10px; letter-spacing: 0.08em; text-transform: uppercase; color: var(--paper); }
  h4 { font-size: 0.78rem; margin: 16px 0 6px; letter-spacing: 0.06em; text-transform: uppercase; color: var(--muted); }
  /* "Card" treatment, 2026-09-17, from Bishop Fox's mockup: rounder radius + two small
     corner-rivet dots (::before/::after) instead of the plain sharp-corner box. */
  .panel {
    position: relative; background: var(--panel); border: 1px solid var(--hairline);
    border-radius: var(--bf-radius); padding: 24px 26px; margin-bottom: 20px;
  }
  .panel::before, .panel::after {
    content: ""; position: absolute; top: 9px; width: 5px; height: 5px; border-radius: 50%;
    background: radial-gradient(circle at 35% 30%, #4a4a54, var(--bf-bg-card-2) 75%);
    box-shadow: 0 0 0 1px rgba(255,255,255,0.04);
  }
  .panel::before { left: 9px; }
  .panel::after { right: 9px; }
  label {
    display: block; font-size: 0.72rem; color: var(--muted); margin: 12px 0 4px;
    letter-spacing: 0.06em; text-transform: uppercase;
  }
  textarea, input[type=text], input[type=number], select {
    width: 100%; background: var(--bf-bg-code); color: var(--text); border: 1px solid var(--hairline);
    border-radius: var(--bf-radius-sm); padding: 8px 10px; font-family: var(--mono); font-size: 0.85rem;
  }
  textarea:focus, input:focus, select:focus { outline: none; border-color: var(--teal); box-shadow: 0 0 0 3px var(--teal-dim); }
  textarea { min-height: 140px; resize: vertical; }
  .row { display: flex; gap: 16px; flex-wrap: wrap; }
  .row > div { flex: 1; min-width: 180px; }
  .checklist { max-height: 180px; overflow: auto; border: 1px solid var(--hairline); border-radius: var(--bf-radius-sm); padding: 8px; background: var(--bf-bg-code); }
  .checklist label {
    display: flex; align-items: center; gap: 6px; margin: 4px 0; color: var(--text);
    font-size: 0.8rem; text-transform: none; letter-spacing: normal; white-space: nowrap;
  }
  .checklist input { width: auto; accent-color: var(--bf-accent); }
  /* Badge pill shape, 2026-09-17, from Bishop Fox's mockup -- same red=destructive/amber=adverse
     colors this project already used (that convention is this project's own risk-tier language,
     not a Bishop Fox brand color, so it's kept as-is; only the shape/weight changed to a pill). */
  .destructive-tag, .adverse-tag {
    display: inline-block; font-family: var(--sans); font-size: 0.6rem; font-weight: 700;
    letter-spacing: 0.04em; padding: 2px 7px; border-radius: 4px; margin-left: 8px;
    white-space: nowrap; border: 1px solid transparent; text-transform: uppercase; cursor: help;
  }
  .destructive-tag { color: var(--red); background: var(--red-dim); border-color: rgba(255,59,48,0.3); }
  .adverse-tag { color: var(--amber); background: var(--amber-dim); border-color: rgba(255,176,32,0.3); }
  button {
    background: var(--amber); color: #1a1200; border: none; border-radius: 2px; padding: 10px 18px;
    font-family: var(--mono); font-size: 0.82rem; letter-spacing: 0.05em; text-transform: uppercase;
    cursor: pointer; margin-top: 14px; font-weight: 600;
  }
  button.secondary { background: var(--panel-in); color: var(--text); border: 1px solid var(--hairline); }
  button.danger { background: var(--red); color: #fff; }
  button:disabled { opacity: 0.45; cursor: default; }
  /* CTA pushbutton, 2026-09-17: adopted wholesale from Bishop Fox's mockup (replaces the
     earlier amber bezel-button design) — a smaller icon-only circular button with a caption
     pill below it, one per tab's "go" moment (Run Scan, Start Discovery), plus the
     confirmation gate's own final trigger (Confirm and Run). The mockup's own example only
     covers the routine case (a single neutral-dark .cta); Confirm and Run keeps this page's
     existing red = higher-consequence convention (matching .destructive-tag/.danger) as a
     color variant of the same shape, since the mockup doesn't define its own two-step-confirm
     button and dropping that distinction would lose a real safety signal. */
  .cta-row { display: flex; justify-content: center; margin-top: 28px; }
  .cta-unit { display: flex; flex-direction: column; align-items: center; gap: 12px; }
  .cta {
    display: flex; align-items: center; justify-content: center;
    width: 76px; height: 76px; border-radius: 50%; border: none; cursor: pointer;
    background: radial-gradient(circle at 38% 32%, #333136, #1c1a1e 75%);
    box-shadow:
      0 0 0 3px var(--ground), 0 0 0 5px #4a4850, 0 0 0 6px #221f24,
      inset 0 1px 1px rgba(255,255,255,0.08), inset 0 -6px 10px rgba(0,0,0,0.55),
      0 6px 0 #08070a, 0 11px 18px rgba(0,0,0,0.55);
    color: #d8d6db; transition: transform 0.08s ease, box-shadow 0.08s ease, filter 0.08s ease;
  }
  .cta svg { width: 24px; height: 24px; }
  .cta:hover { filter: brightness(1.15); }
  .cta:active {
    transform: translateY(5px);
    box-shadow:
      0 0 0 3px var(--ground), 0 0 0 5px #4a4850, 0 0 0 6px #221f24,
      inset 0 2px 4px rgba(0,0,0,0.6), 0 1px 0 #08070a, 0 3px 8px rgba(0,0,0,0.5);
  }
  .cta:disabled { filter: grayscale(0.6) brightness(0.6); cursor: default; }
  .cta-caption {
    font-family: var(--mono); font-size: 0.68rem; font-weight: 600; letter-spacing: 0.12em;
    text-transform: uppercase; color: var(--muted); background: var(--bf-bg-code);
    border: 1px solid var(--hairline); border-radius: 999px; padding: 5px 14px;
  }
  /* Confirm and Run's own color variant -- same shape, red-toned ring to keep this page's
     destructive/adverse-gated-action convention visible. */
  #confirm-run-btn {
    background: radial-gradient(circle at 38% 32%, #4a2a28, #1c1a1e 75%);
    box-shadow:
      0 0 0 3px var(--ground), 0 0 0 5px var(--red-dim), 0 0 0 6px #221f24,
      inset 0 1px 1px rgba(255,255,255,0.08), inset 0 -6px 10px rgba(0,0,0,0.55),
      0 6px 0 #08070a, 0 11px 18px rgba(0,0,0,0.55);
    color: var(--red);
  }
  #confirm-run-btn:active {
    box-shadow:
      0 0 0 3px var(--ground), 0 0 0 5px var(--red-dim), 0 0 0 6px #221f24,
      inset 0 2px 4px rgba(0,0,0,0.6), 0 1px 0 #08070a, 0 3px 8px rgba(0,0,0,0.5);
  }
  /* Matches Bishop Fox's own "toggle-pair" (Active ARP scan / Passive listen in their mockup). */
  .mode-switch { display: flex; gap: 8px; margin-bottom: 6px; }
  .mode-btn {
    flex: 1; background: var(--bf-bg-code); color: var(--muted); border: 1px solid var(--hairline);
    margin-top: 0;
  }
  .mode-btn.active { background: var(--bf-accent-soft); color: var(--text); border-color: var(--bf-accent-border); }
  .toggle-row { display: flex; align-items: center; gap: 8px; margin-top: 14px; }
  .toggle-row input { width: auto; accent-color: var(--bf-accent); }
  .toggle-row label { margin: 0; text-transform: none; letter-spacing: normal; font-size: 0.82rem; }
  #confirm-box {
    display: none; border: 1px solid var(--red); background: var(--red-dim); border-radius: 2px;
    padding: 14px 16px; margin-top: 14px; font-size: 0.85rem; font-family: var(--sans);
  }
  #confirm-box ul { margin: 8px 0; padding-left: 20px; }
  #run-view { display: none; }
  pre#job-status { background: var(--panel-in); border: 1px solid var(--hairline); border-radius: 2px; padding: 10px; font-size: 0.8rem; white-space: pre-wrap; }
  table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 0.8rem; }
  th, td { text-align: left; border-bottom: 1px solid var(--hairline); padding: 6px 8px; }
  th { color: var(--muted); font-weight: 600; font-size: 0.7rem; letter-spacing: 0.05em; text-transform: uppercase; }
  .status-confirmed { color: var(--red); font-weight: 600; }
  .status-pending { color: var(--muted); }
  .status-done { color: var(--green); }
  .mono-note { color: var(--muted); font-size: 0.8rem; margin-bottom: 8px; }
  #discovery-error { margin-top: 10px; padding: 8px 12px; border-radius: 6px; font-size: 0.85rem;
    color: var(--danger, #e5484d); border: 1px solid var(--danger, #e5484d);
    background: color-mix(in srgb, var(--danger, #e5484d) 10%, transparent); }
  .throbber { display: none; width: 14px; height: 14px; border: 2px solid var(--border, #2a2f3a);
    border-top-color: var(--accent, #4f8cff); border-radius: 50%; animation: spin 0.8s linear infinite;
    vertical-align: middle; margin-right: 7px; }
  .throbber.on { display: inline-block; }
  .throbber.stalled { border-top-color: var(--warn, #e8a33d); }
  @keyframes spin { to { transform: rotate(360deg); } }
  tr.row-flash > td { animation: rowflash 1.8s ease-out; }
  @keyframes rowflash { 0%, 40% { background: var(--amber, #e8a33d); color: #111; } 100% { background: transparent; } }

  /* ── Search bar, empty-state, cred-card — 2026-09-17, adopted from Bishop Fox's mockup ──── */
  .search-bar { position: relative; margin-bottom: 18px; }
  .search-bar input { padding-left: 34px; }
  .search-bar svg { position: absolute; left: 11px; top: 50%; transform: translateY(-50%); width: 14px; height: 14px; color: var(--muted); pointer-events: none; }

  .empty-state {
    text-align: center; padding: 46px 20px; color: var(--muted); font-size: 0.86rem;
    border: 1px dashed var(--hairline); border-radius: var(--bf-radius);
  }

  .cred-card { border: 1px solid var(--hairline); border-radius: var(--bf-radius); padding: 17px 19px; margin-bottom: 14px; background: var(--bf-bg-card-2); }
  .cred-card:last-child { margin-bottom: 0; }
  .cred-card h3 { font-size: 0.95rem; font-weight: 700; margin: 0 0 4px; display: flex; align-items: center; flex-wrap: wrap; gap: 2px; color: var(--text); text-transform: none; letter-spacing: normal; }
  .cred-card .protocol-tag { font-family: var(--mono); font-size: 0.7rem; color: var(--teal); margin-left: 6px; font-weight: 500; }
  .cred-card .check-id { font-family: var(--mono); font-size: 0.74rem; color: var(--muted); margin-bottom: 12px; display: block; }
  .cred-card ul { margin: 0 0 12px; padding-left: 18px; }
  .cred-card li { font-family: var(--mono); font-size: 0.82rem; margin-bottom: 4px; color: var(--text); }
  .cred-card .desc { font-size: 0.81rem; color: var(--muted); margin: 0; }
  .method-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 6px; vertical-align: middle; }
  .method-dot.arp_active { background: var(--amber); }
  .method-dot.arp_passive { background: var(--muted); }
  .method-dot.sparkplug_b { background: var(--teal); }
  .method-dot.micom_courier_active { background: #c77dff; }
  .method-dot.mqtt_active { background: var(--teal); }
  .method-dot.factorytalk_rna_active { background: #ff7a7a; }
  .discovery-identity-sub { display: block; color: var(--muted); font-size: 0.75em; margin-top: 2px; }
  footer { text-align: center; color: var(--muted); font-size: 0.75rem; margin: 32px 0 8px; letter-spacing: 0.04em; }
</style>
</head>
<body>
  <header class="topbar">
    <div class="topbar-left">
      <div class="logo"><img class="logo-img" src="/static/bishopfox-logo.png" alt="Bishop Fox"></div>
      <div class="topbar-divider"></div>
      <div class="app-label">
        <span class="app-title">icsScanner</span>
        <span class="app-subtitle">Active Probe Control &middot; Web Panel</span>
      </div>
    </div>
    <div class="topbar-right">
      <div class="light-system" title="Run status">
        <div class="light-item"><span class="bulb" id="lamp-healthy"></span><span class="label">HEALTHY</span></div>
        <div class="light-item"><span class="bulb" id="lamp-active"></span><span class="label">ACTIVE</span></div>
        <div class="light-item"><span class="bulb" id="lamp-error"></span><span class="label">ERROR</span></div>
      </div>
      <button type="button" class="laptop-pill" id="density-toggle" onclick="toggleDensity()" title="Reduce gutters and enlarge text for small laptop screens">
        <span class="switch"></span>
        <span id="density-toggle-label">LAPTOP VIEW: OFF</span>
      </button>
    </div>
  </header>

  <div class="warn-strip">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0Z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>
    <div><strong>Authorized use only</strong> — this can send live protocol traffic to real ICS/OT devices. <a href="#full-warning-notice">Full notice below.</a></div>
  </div>

  <div class="tab-switch">
    <button class="tab-btn active" id="tab-scanner-btn" onclick="switchTab('scanner')">Scanner</button>
    <button class="tab-btn" id="tab-discovery-btn" onclick="switchTab('discovery')">Discovery</button>
    <button class="tab-btn" id="tab-fieldref-btn" onclick="switchTab('fieldref')">Field Reference</button>
    <button class="tab-btn" id="tab-credentials-btn" onclick="switchTab('credentials')">Credentials</button>
    <button class="tab-btn" id="tab-notauto-btn" onclick="switchTab('notauto')">Not Automatable</button>
  </div>

  <!-- ══════════════════════════ SCANNER VIEW ══════════════════════════ -->
  <div class="view active" id="scanner-view">
    <div class="panel" id="form-panel">
      <div id="inventory-simple-wrap">
        <label for="inventory-simple">Targets</label>
        <textarea id="inventory-simple" spellcheck="false">192.168.1.50</textarea>
        <div class="mono-note">Add one target per line (an IP or hostname). Need a port,
          vendor hint, or a credential reference? Use the
          <a href="#" onclick="setInventoryMode('advanced'); return false;">advanced (YAML) editor</a> instead.</div>
      </div>
      <div id="inventory-advanced-wrap" style="display:none;">
        <label for="inventory">Target inventory (YAML)</label>
        <textarea id="inventory" spellcheck="false"># See templates/target-inventory.example.yaml for the full format.
targets:
  - host: 192.168.1.50</textarea>
        <div class="mono-note">
          <a href="#" onclick="setInventoryMode('simple'); return false;">&larr; Back to the simple list</a>
        </div>
      </div>

      <div class="row">
        <div style="flex: 1;">
          <label>Protocols (empty = all)</label>
          <div class="checklist" id="protocol-list"><i>loading&hellip;</i></div>
        </div>
        <div style="flex: 1;">
          <label>Vendors (empty = all)</label>
          <div class="checklist" id="vendor-list"><i>loading&hellip;</i></div>
        </div>
        <div style="flex: 2; min-width: 320px;">
          <label>Check IDs (empty = all matching protocol/vendor filter)</label>
          <div class="checklist" id="check-list"><i>loading&hellip;</i></div>
        </div>
      </div>

      <div class="row">
        <div>
          <label for="max-concurrent">Max concurrent targets</label>
          <input type="number" id="max-concurrent" value="4" min="1">
        </div>
        <div>
          <label for="output-dir">Output directory</label>
          <input type="text" id="output-dir" value="./output">
        </div>
      </div>

      <div class="toggle-row">
        <input type="checkbox" id="include-adverse">
        <label for="include-adverse" title="Real login attempts with no confirmed lockout risk and no device write — still a live authentication attempt, just the lower-consequence tier.">Include adverse checks (plain login attempt, no known lockout risk)</label>
      </div>
      <div class="toggle-row">
        <input type="checkbox" id="include-destructive">
        <label for="include-destructive" title="Real login attempts where the target has a documented lockout-after-N-attempts mechanism, the check itself writes to the device to verify the credential, or exploitation creates a new account. Independent of 'adverse' — neither is a subset of the other.">Include destructive checks (confirmed lockout risk, device write, or account creation)</label>
      </div>

      <div class="cta-row">
        <div class="cta-unit">
          <button class="cta" id="run-btn" onclick="submitScan(false)" aria-label="Run Scan">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="5 3 19 12 5 21 5 3"></polygon></svg>
          </button>
          <span class="cta-caption">Run scan</span>
        </div>
      </div>

      <div id="confirm-box">
        <b>Confirm live run</b>
        <div id="confirm-details"></div>
        <div class="cta-row">
          <div class="cta-unit">
            <button class="cta" id="confirm-run-btn" onclick="submitScan(true)" aria-label="Confirm and Run">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="5 3 19 12 5 21 5 3"></polygon></svg>
            </button>
            <span class="cta-caption">Confirm and run</span>
          </div>
        </div>
        <button class="secondary" onclick="cancelConfirm()">Cancel</button>
      </div>
    </div>

    <div class="panel" id="run-view">
      <h3>Run status</h3>
      <pre id="job-status">&hellip;</pre>
      <div class="toggle-row">
        <input type="checkbox" id="include-evidence-toggle">
        <label for="include-evidence-toggle">Include raw evidence in HTML/CSV report downloads</label>
      </div>
      <div id="results"></div>
    </div>
  </div>

  <!-- ══════════════════════════ DISCOVERY VIEW ═════════════════════════ -->
  <div class="view" id="discovery-view">
    <div class="panel" id="discovery-config-panel">
      <div class="mode-switch">
        <button class="mode-btn active" id="mode-btn-active" onclick="setDiscoveryMode('active')">Active Scan</button>
        <button class="mode-btn" id="mode-btn-passive" onclick="setDiscoveryMode('passive')">Passive Listen</button>
        <button class="mode-btn" id="mode-btn-sniff" onclick="setDiscoveryMode('sniff')">Passive Sniff (SPAN/pcap)</button>
      </div>

      <div id="discovery-active-fields">
        <label for="disc-method">Method</label>
        <select id="disc-method" onchange="onDiscoveryMethodChange()">
          <option value="arp">ARP sweep (broadcast, any device)</option>
          <option value="micom_courier">MiCOM Courier / IEC 103 (ONC-RPC portmapper query)</option>
          <option value="mqtt">MQTT (CONNECT/CONNACK probe)</option>
          <option value="protocol_probe">Protocol sweep (S7comm / Modbus / OPC-UA / EtherNet-IP / SLMP / XGT / UMAS / MSSQL / PCOM)</option>
          <option value="codesys">CODESYS V3 name-service broadcast (ABB AC500 / Hitachi / Opto22 / Schneider / WAGO / Beckhoff)</option>
        </select>
        <label for="disc-cidr">Subnet (CIDR)</label>
        <input type="text" id="disc-cidr" placeholder="192.168.1.0/24">
        <div class="row">
          <div id="disc-iface-row">
            <label for="disc-iface">Interface (blank finds it automatically)</label>
            <input type="text" id="disc-iface" placeholder="eth0">
          </div>
          <div>
            <label for="disc-timeout">Reply window (seconds)</label>
            <input type="number" id="disc-timeout" value="2" min="1">
          </div>
        </div>
        <div id="disc-mqtt-fields" style="display:none;">
          <div class="row">
            <div>
              <label for="disc-mqtt-port">Broker port</label>
              <input type="number" id="disc-mqtt-port" value="1883">
            </div>
          </div>
          <div class="toggle-row">
            <input type="checkbox" id="disc-mqtt-sparkplug" checked>
            <label for="disc-mqtt-sparkplug">Auto-listen for Sparkplug B on any broker accepting anonymous connections</label>
          </div>
        </div>
        <div id="disc-probe-fields" style="display:none;">
          <label>Protocols to sweep (each probed on its default port; read-only identity probes)</label>
          <div id="disc-probe-list" class="toggle-row" style="flex-wrap:wrap; gap:10px;">
            <span class="label" style="color:var(--muted)">loading…</span>
          </div>
        </div>
        <div class="toggle-row">
          <input type="checkbox" id="disc-force">
          <label for="disc-force">Allow ranges larger than /20 (4096 hosts)</label>
        </div>
      </div>

      <div id="discovery-passive-fields" style="display:none;">
        <div class="row">
          <div>
            <label for="disc-duration">Listen duration (seconds)</label>
            <input type="number" id="disc-duration" value="30" min="1">
          </div>
          <div>
            <label for="disc-iface-passive">Interface (blank finds it automatically)</label>
            <input type="text" id="disc-iface-passive" placeholder="eth0">
          </div>
        </div>
        <label>Protocols to listen for</label>
        <div class="checklist" id="discovery-protocol-list"><i>loading&hellip;</i></div>
        <div id="sparkplug-broker-fields" style="display:none;">
          <div class="row">
            <div>
              <label for="disc-broker-host">Sparkplug B broker host</label>
              <input type="text" id="disc-broker-host" placeholder="192.168.1.5">
            </div>
            <div>
              <label for="disc-broker-port">Broker port</label>
              <input type="number" id="disc-broker-port" value="1883">
            </div>
          </div>
        </div>
      </div>

      <div id="discovery-sniff-fields" style="display:none;">
        <label for="disc-sniff-source">Source (this mode transmits nothing)</label>
        <select id="disc-sniff-source" onchange="onSniffSourceChange()">
          <option value="span">Live SPAN / mirror / TAP interface (RX-only)</option>
          <option value="pcap">Offline capture file (.pcap on the server)</option>
          <option value="zeek_logs">Zeek / ICSNPP identity logs (hybrid)</option>
        </select>
        <div id="disc-sniff-span-fields">
          <div class="row">
            <div>
              <label for="disc-sniff-iface">Interface (blank finds it automatically)</label>
              <input type="text" id="disc-sniff-iface" placeholder="eth1">
            </div>
            <div>
              <label for="disc-sniff-window">Capture window (seconds)</label>
              <input type="number" id="disc-sniff-window" value="60" min="1">
            </div>
          </div>
        </div>
        <div id="disc-sniff-pcap-fields" style="display:none;">
          <label for="disc-sniff-pcap-file">Upload a capture (.pcap/.pcapng) from your browser</label>
          <input type="file" id="disc-sniff-pcap-file" accept=".pcap,.pcapng,.cap">
          <label for="disc-sniff-pcap" style="margin-top:8px;">… or a capture file path already on the server</label>
          <input type="text" id="disc-sniff-pcap" placeholder="/path/to/plant-span.pcap">
        </div>
        <div id="disc-sniff-zeek-fields" style="display:none;">
          <label for="disc-sniff-zeek">Zeek log directory (on the server)</label>
          <input type="text" id="disc-sniff-zeek" placeholder="/opt/zeek/logs/current">
        </div>
        <div class="toggle-row">
          <input type="checkbox" id="disc-sniff-cve" checked>
          <label for="disc-sniff-cve">Correlate assets against the CVE candidate corpus (identity-only)</label>
        </div>
        <div class="toggle-row">
          <input type="checkbox" id="disc-sniff-detections">
          <label for="disc-sniff-detections">Match detection signatures against the traffic (Observed Activity — pcap/SPAN only, pattern-on-wire not confirmed compromise)</label>
        </div>
      </div>

      <div class="cta-row">
        <div class="cta-unit">
          <button class="cta" id="discover-btn" onclick="startDiscovery()" aria-label="Start Discovery">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="5 3 19 12 5 21 5 3"></polygon></svg>
          </button>
          <span class="cta-caption">Start discovery</span>
        </div>
        <div id="discovery-error" role="alert" style="display:none;"></div>
      </div>
    </div>

    <div class="panel" id="discovery-results-panel" style="display:none;">
      <h3>Discovered devices</h3>
      <div class="mono-note"><span class="throbber" id="discovery-throbber"></span><span id="discovery-status">&hellip;</span></div>
      <table id="discovery-table">
        <thead><tr><th></th><th>Identity</th><th>MAC</th><th>Vendor</th><th>Model</th><th>Method</th><th>CVEs</th><th>First seen</th><th>Last seen</th></tr></thead>
        <tbody id="discovery-tbody"></tbody>
      </table>
      <div id="discovery-findings" style="display:none; margin-top:14px;">
        <h3>Passive vulnerability findings</h3>
        <div class="mono-note" id="discovery-findings-note"></div>
        <table id="discovery-findings-table">
          <thead><tr><th>Asset</th><th>Vendor / model</th><th>CVE</th><th>Candidate</th><th>Scope</th></tr></thead>
          <tbody id="discovery-findings-tbody"></tbody>
        </table>
      </div>
      <div id="discovery-detections" style="display:none; margin-top:14px;">
        <h3>Observed activity (passive detections)</h3>
        <div class="mono-note" id="discovery-detections-note"></div>
        <div style="display:flex; gap:8px; align-items:center; margin:8px 0; flex-wrap:wrap;">
          <input type="text" id="det-filter-text" placeholder="filter by host / check / technique" oninput="filterDetections()" style="flex:1; min-width:180px;">
          <select id="det-filter-mode" onchange="filterDetections()">
            <option value="">all modes/types</option>
            <option value="narrow">narrow (recon)</option>
            <option value="broad">broad (exploitation-class)</option>
            <option value="behavioral">behavioral (volumetric)</option>
            <option value="config_exposure">config exposure</option>
            <option value="attack_activity">attack activity</option>
            <option value="reconnaissance">reconnaissance</option>
          </select>
          <span class="mono-note" id="det-filter-count" style="margin:0;"></span>
        </div>
        <table id="discovery-detections-table">
          <thead><tr><th>Target (identity)</th><th>Mode</th><th>Technique(s)</th><th>Count</th><th>Check(s)</th></tr></thead>
          <tbody id="discovery-detections-tbody"></tbody>
        </table>
      </div>
      <button class="secondary" onclick="toggleAllDiscoveryRows(true)">Select All</button>
      <button class="secondary" onclick="toggleAllDiscoveryRows(false)">Select None</button>
      <button onclick="copySelectedToScanner()">Copy Selected to Scanner</button>
      <button class="secondary" onclick="emitDiscoveryTargets()" title="Download the discovered inventory as a pre-hinted target file for an active scan">Download as scan targets</button>
      <div id="discovery-downloads" class="mono-note" style="margin-top:10px;"></div>
    </div>
  </div>

  <!-- ══════════════════════ FIELD REFERENCE VIEW ══════════════════════
       Read-only. No button here ever sends a network request beyond the
       initial page-load fetch — these findings gate LOCAL/physical access
       (a keypad, a touchscreen, a hardware switch) and this tool never
       tests them remotely. Deliberately styled plainly (no amber action
       buttons, no run/copy controls) so it can't be mistaken for the
       Scanner/Discovery tabs' live-probing controls. -->
  <div class="view" id="fieldref-view">
    <div class="mono-note" style="margin-bottom:14px;">
      Reference only &mdash; these require local/physical access (a front-panel keypad, an HMI
      touchscreen, a direct serial/USB connection) and are never tested remotely by this tool.
    </div>
    <div class="search-bar">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="7"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
      <input type="text" id="fieldref-search" placeholder="Search by vendor, device, or keyword&hellip;" oninput="renderFieldRefList()">
    </div>
    <div id="fieldref-list" style="margin-top:14px;"><i>loading&hellip;</i></div>
  </div>

  <!-- Credentials tab: every known default credential in the registry, re-presented from data
       already public in checks/**/*.yaml (see core/credential_list.py). Read-only, same posture
       as Field Reference — no run/copy controls, can't be mistaken for a live-probing tab. -->
  <div class="view" id="credentials-view">
    <div class="mono-note" style="margin-bottom:14px;">
      Reference only &mdash; every default credential already documented in this project's own
      checks, in one searchable table. Viewing this list sends nothing to any device.
    </div>
    <div class="search-bar">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="7"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
      <input type="text" id="credentials-search" placeholder="Search by vendor, protocol, or check id&hellip;" oninput="renderCredentialsList()">
    </div>
    <div id="credentials-list" style="margin-top:14px;"><i>loading&hellip;</i></div>
  </div>

  <!-- Not Automatable tab: real, primary-source-verified default credentials that CANNOT become an
       automated check (form-login field names unknown, derived/architectural mismatch, proprietary
       protocol with no executor, wireless/out of scope). Read-only, same posture as Field Reference
       and Credentials — no run/copy controls. See core/not_automatable_list.py. -->
  <div class="view" id="notauto-view">
    <div class="mono-note" style="margin-bottom:14px;">
      Reference only &mdash; verified default credentials this scanner deliberately does NOT automate,
      with the reason for each. Nothing here is a runnable check; viewing this list sends nothing to
      any device.
    </div>
    <div class="search-bar">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="7"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
      <input type="text" id="notauto-search" placeholder="Search by vendor, protocol, reason, or check id&hellip;" oninput="renderNotAutomatableList()">
    </div>
    <div id="notauto-list" style="margin-top:14px;"><i>loading&hellip;</i></div>
  </div>

  <footer id="check-count-footer">&hellip;</footer>
  <div class="footer-links"><a href="#credits-notice" onclick="var d=document.getElementById('credits-notice'); if(d) d.open=true;">Credits &amp; CVEs</a></div>

  <div class="notice-light" id="full-warning-notice">
    <div class="notice-head">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0Z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>
      <h2>Authorized use only</h2>
    </div>
    <p>This sends live protocol traffic to ICS/OT devices, including real login attempts against
    published factory-default credentials when adverse and/or destructive checks are enabled, and
    real broadcast ARP requests when running an active discovery scan. Only probe devices and
    segments you own or have explicit written permission to test. Coordinate with plant/facility
    operators before running. Never target production systems without approval.</p>
    <p><strong>Adverse</strong> and <strong>destructive</strong> both mean a real, live
    authentication attempt against the target — neither is a passive/read-only probe. The split
    is about WHY the check is marked at all: <span class="adverse-tag" style="margin:0;">adverse</span>
    is a plain login attempt with no confirmed lockout risk and no device write;
    <span class="destructive-tag" style="margin:0;">destructive</span> means the target device
    has a documented lockout-after-N-attempts mechanism, or the check itself writes to the
    device (e.g. a Modbus register write) as part of verifying the credential, or exploitation
    would create a new account. Findings where success could cause PHYSICAL actuation (e.g.
    robot motion, breaker control) are never exposed as a toggleable check here at all, by
    design — they live entirely outside this scanner, in a separate standalone tier of tools
    this web UI has no way to invoke (see this project's own methodology documentation).</p>
  </div>

  <details class="notice-light" id="credits-notice">
    <summary class="notice-head">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="8" r="6"></circle><path d="M15.477 12.89 17 22l-5-3-5 3 1.523-9.11"></path></svg>
      <h2>Credits</h2>
      <svg class="notice-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="m6 9 6 6 6-6"></path></svg>
    </summary>
    <p>Research and development by <strong>Shad Malloy</strong> and <strong>Zoe Duncan</strong>.</p>
    <p>CVEs assigned from this project's vulnerability research. All four are in the RT-Labs SOEM
    EtherCAT master (versions &le;2.0.0 affected, fixed in 2.0.1), coordinated through RT-Labs under
    advisory <a href="https://rt-labs.com/wp-content/uploads/2026/10/RRTL-260921-01.pdf" target="_blank" rel="noopener noreferrer">RRTL-260921-01</a>
    (published 2026-10-15):</p>
    <ul>
      <li><code>CVE-2026-82946</code> &mdash; NULL-pointer dereference in mailbox error handling (CVSS 6.5) &mdash; sole credit.</li>
      <li><code>CVE-2026-70388</code> &mdash; mailbox length underflow leading to an out-of-bounds write (CVSS 8.3) &mdash; co-credited.</li>
      <li><code>CVE-2026-82943</code> &mdash; out-of-bounds read on an unchecked length (CVSS 6.5) &mdash; co-credited.</li>
      <li><code>CVE-2026-82947</code> &mdash; out-of-bounds reads in frame processing (CVSS 7.1) &mdash; co-credited.</li>
    </ul>
    <p>The co-credited entries were fixed in a release that also addressed findings from other
    independent reporters; see the RT-Labs advisory for the full acknowledgement list.</p>
  </details>

<script>
let selectedChecksMeta = [];
let lastDiscoveryDevices = [];

/* HTML-escape any server-derived string before it goes into an innerHTML template or a quoted
   attribute value. Safe for both contexts (escapes < > & " '). Every ${...} interpolation of a
   value that originates from an API response — check metadata, discovered-device fields, job
   summaries, error text — must pass through this. Candidate-stub descriptions and reference URLs
   in particular can carry text copied verbatim from an external advisory feed (see
   core/csaf_feed.py), so this is a real injection boundary, not just tidiness. */
function esc(v) {
  if (v === null || v === undefined) return '';
  return String(v)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/* ── Laptop density toggle ─────────────────────────────────────────── */
function applyDensity(on) {
  document.documentElement.dataset.density = on ? 'laptop' : '';
  document.getElementById('density-toggle').classList.toggle('on', on);
  document.getElementById('density-toggle-label').textContent = `LAPTOP VIEW: ${on ? 'ON' : 'OFF'}`;
  localStorage.setItem('icsscanner-density-laptop', on ? '1' : '0');
}
function toggleDensity() {
  applyDensity(document.documentElement.dataset.density !== 'laptop');
}

/* ── Tabs ──────────────────────────────────────────────────────────── */
function switchTab(name) {
  document.getElementById('scanner-view').classList.toggle('active', name === 'scanner');
  document.getElementById('discovery-view').classList.toggle('active', name === 'discovery');
  document.getElementById('fieldref-view').classList.toggle('active', name === 'fieldref');
  document.getElementById('credentials-view').classList.toggle('active', name === 'credentials');
  document.getElementById('notauto-view').classList.toggle('active', name === 'notauto');
  document.getElementById('tab-scanner-btn').classList.toggle('active', name === 'scanner');
  document.getElementById('tab-discovery-btn').classList.toggle('active', name === 'discovery');
  document.getElementById('tab-fieldref-btn').classList.toggle('active', name === 'fieldref');
  document.getElementById('tab-credentials-btn').classList.toggle('active', name === 'credentials');
  document.getElementById('tab-notauto-btn').classList.toggle('active', name === 'notauto');
}

/* ── Status lamps ──────────────────────────────────────────────────── */
let jobRunning = false;

function setLamps(state) {
  const healthy = document.getElementById('lamp-healthy');
  const active = document.getElementById('lamp-active');
  const error = document.getElementById('lamp-error');
  healthy.className = 'bulb'; active.className = 'bulb'; error.className = 'bulb';
  if (state === 'running') active.classList.add('lit-active');
  else if (state === 'trip') error.classList.add('lit-error');
  else if (state === 'healthy') healthy.classList.add('lit-healthy');
  /* state === 'idle' -> all lamps stay dim */
}

/* Server-liveness heartbeat for the HEALTHY/TRIP lamps at rest. Deliberately never touches the
   lamps while a scan/discovery job is in flight (jobRunning) so it can't clobber that job's own
   AMBER/TRIP/HEALTHY result out from under it — the heartbeat only speaks when no job is. */
async function heartbeat() {
  if (jobRunning) return;
  try {
    const res = await fetch('/api/health');
    setLamps(res.ok ? 'healthy' : 'trip');
  } catch (e) {
    setLamps('trip');
  }
}
function startHeartbeat() {
  heartbeat();
  setInterval(heartbeat, 5000);
}

/* ── Scanner tab (unchanged behavior, restyled markup) ────────────── */
async function loadChecks() {
  const res = await fetch('/api/checks');
  const checks = await res.json();
  selectedChecksMeta = checks;
  const protocols = [...new Set(checks.map(c => c.protocol))].sort();
  document.getElementById('protocol-list').innerHTML = protocols.map(p =>
    `<label><input type="checkbox" class="proto-cb" value="${esc(p)}"> ${esc(p)}</label>`
  ).join('') || '<i>No checks loaded.</i>';
  const vendors = [...new Set(checks.map(c => c.vendor).filter(Boolean))].sort();
  document.getElementById('vendor-list').innerHTML = vendors.map(v =>
    `<label><input type="checkbox" class="vendor-cb" value="${v}"> ${v}</label>`
  ).join('') || '<i>No vendor hints on any loaded check.</i>';
  renderCheckList(checks);
  document.getElementById('check-count-footer').textContent =
    checks.length + (checks.length === 1 ? ' check loaded' : ' checks loaded');
}

const RISK_REASON_LABELS = {
  login: 'login', lockout: 'lockout', device_write: 'device write', account_creation: 'account creation',
};

function riskTag(c) {
  if (!c.risk_tier) return '';
  const reasons = (c.risk_reason || []).map(r => RISK_REASON_LABELS[r] || r).join(', ');
  if (c.risk_tier === 'adverse') {
    return `<span class="adverse-tag" title="Plain login attempt, no confirmed lockout risk, no device write.">adverse - login</span>`;
  }
  const suffix = reasons || 'unclassified, defaults to the cautious tier';
  return `<span class="destructive-tag" title="Confirmed lockout risk and/or a device write and/or account creation — see 01-METHODOLOGY-AND-CHECKLISTS.md.">destructive - ${esc(suffix)}</span>`;
}

function renderCheckList(checks) {
  document.getElementById('check-list').innerHTML = checks.map(c =>
    `<label title="${esc(c.description)}">
      <input type="checkbox" class="check-cb" value="${esc(c.check_id)}"> ${esc(c.check_id)}
      ${c.vendor ? `<span class="mono-note" style="margin:0 0 0 6px;">${esc(c.vendor)}</span>` : ''}
      ${riskTag(c)}
    </label>`
  ).join('') || '<i>No checks match this filter.</i>';
}

/* ── Field Reference (physical-access-only findings, read-only) ──────── */
let fieldRefItems = [];

async function loadFieldRef() {
  const res = await fetch('/api/physical-access-checks');
  fieldRefItems = await res.json();
  renderFieldRefList();
}

function renderFieldRefList() {
  const q = document.getElementById('fieldref-search').value.toLowerCase();
  const matches = fieldRefItems.filter(item =>
    !q || [item.vendor, item.check_id, item.summary, item.description].join(' ').toLowerCase().includes(q)
  );
  document.getElementById('fieldref-list').innerHTML = matches.map((item, i) => `
    <div class="panel fieldref-item">
      <div class="fieldref-head" onclick="toggleFieldRefItem(${i})" style="cursor:pointer;">
        <h3 style="display:inline;">${esc(item.vendor)}</h3>
        <span class="mono-note" style="margin:0 0 0 8px;">${esc(item.check_id.replace('candidate-', ''))}</span>
      </div>
      <div class="mono-note" style="margin-top:6px;">${esc(item.summary)}</div>
      <div id="fieldref-body-${i}" style="display:none; margin-top:10px;">
        ${item.steps.length
          ? `<ol>${item.steps.map(s => `<li>${esc(s)}</li>`).join('')}</ol>`
          : ''}
        ${item.references.length
          ? `<h4>Source</h4><ul>${item.references.map(r => `<li>${esc(r)}</li>`).join('')}</ul>`
          : ''}
      </div>
    </div>
  `).join('') || '<div class="empty-state">No matching reference entries.</div>';
}

function toggleFieldRefItem(i) {
  const body = document.getElementById(`fieldref-body-${i}`);
  body.style.display = body.style.display === 'none' ? 'block' : 'none';
}

/* ── Credentials (full registry, read-only) ───────────────────────────── */
let credentialItems = [];

async function loadCredentials() {
  const res = await fetch('/api/credential-list');
  credentialItems = await res.json();
  renderCredentialsList();
}

function renderCredentialsList() {
  const q = document.getElementById('credentials-search').value.toLowerCase();
  const matches = credentialItems.filter(item =>
    !q || [item.vendor, item.product, item.protocol, item.check_id].join(' ').toLowerCase().includes(q)
  );
  document.getElementById('credentials-list').innerHTML = matches.map(item => {
    const credsHtml = item.via_description
      ? `<p class="desc" style="margin:0 0 12px;">See description &mdash; this check's default value is a device-computed sentinel or hardcoded value, not a fixed username/password pair.</p>`
      : `<ul>${item.credentials.map(c =>
          `<li>${esc(c.username)} / ${esc(c.password)}</li>`
        ).join('')}</ul>`;
    return `
    <div class="cred-card">
      <h3>${esc(item.vendor || 'Unknown vendor')}${item.product ? ` <span class="mono-note" style="margin:0;">(${esc(item.product)})</span>` : ''}<span class="protocol-tag">${esc(item.protocol)}</span>${riskTag(item)}</h3>
      <span class="check-id">${esc(item.check_id)}</span>
      ${credsHtml}
      <p title="${esc(item.description)}" class="desc" style="cursor: help;">${esc(item.description.slice(0, 160))}${item.description.length > 160 ? '&hellip;' : ''}</p>
    </div>
  `;
  }).join('') || '<div class="empty-state">No matching entries.</div>';
}

/* ── Not Automatable (verified creds that can't become a check, read-only) ── */
let notAutoItems = [];

async function loadNotAutomatable() {
  const res = await fetch('/api/not-automatable');
  notAutoItems = await res.json();
  renderNotAutomatableList();
}

function renderNotAutomatableList() {
  const q = document.getElementById('notauto-search').value.toLowerCase();
  const matches = notAutoItems.filter(item =>
    !q || [item.vendor, item.protocol, item.check_id, item.category_label, item.reason].join(' ').toLowerCase().includes(q)
  );
  // group by category_label
  const groups = {};
  matches.forEach(item => { (groups[item.category_label] = groups[item.category_label] || []).push(item); });
  const html = Object.keys(groups).sort().map(label => `
    <h3 style="margin:18px 0 8px; border-bottom:1px solid var(--border); padding-bottom:4px;">${esc(label)} <span class="mono-note" style="margin:0;">(${groups[label].length})</span></h3>
    ${groups[label].map(item => `
      <div class="cred-card">
        <h3>${esc(item.vendor || 'Unknown vendor')}<span class="protocol-tag">${esc(item.protocol)}</span></h3>
        <span class="check-id">${esc(item.check_id)}</span>
        <ul><li><strong>Credential:</strong> ${esc(item.credential)}</li></ul>
        <p class="desc" style="margin:0 0 6px;"><strong>Why not automatable:</strong> ${esc(item.reason)}</p>
        <p class="desc" style="margin:0; font-style:italic;">Source: ${esc(item.source)}</p>
      </div>
    `).join('')}
  `).join('');
  document.getElementById('notauto-list').innerHTML = html || '<div class="empty-state">No matching entries.</div>';
}

function applyCheckFilters() {
  const activeProtocols = [...document.querySelectorAll('.proto-cb:checked')].map(cb => cb.value);
  const activeVendors = [...document.querySelectorAll('.vendor-cb:checked')].map(cb => cb.value);
  const filtered = selectedChecksMeta.filter(c =>
    (!activeProtocols.length || activeProtocols.includes(c.protocol)) &&
    (!activeVendors.length || activeVendors.includes(c.vendor))
  );
  renderCheckList(filtered);
}

document.addEventListener('change', (e) => {
  if (e.target.classList.contains('proto-cb') || e.target.classList.contains('vendor-cb')) {
    applyCheckFilters();
  }
  if (e.target.id === 'discovery-protocol-cb-sparkplug_b') {
    document.getElementById('sparkplug-broker-fields').style.display = e.target.checked ? 'block' : 'none';
  }
});

function currentPolicy() {
  return {
    protocols: [...document.querySelectorAll('.proto-cb:checked')].map(cb => cb.value),
    check_ids: [...document.querySelectorAll('.check-cb:checked')].map(cb => cb.value),
    include_destructive: document.getElementById('include-destructive').checked,
    include_adverse: document.getElementById('include-adverse').checked,
    max_concurrent_targets: parseInt(document.getElementById('max-concurrent').value || '4', 10),
    output_dir: document.getElementById('output-dir').value || './output',
  };
}

// Target inventory has two views over the same underlying #inventory YAML textarea (never
// two separate sources of truth): a simple one-line-per-host list (the default) and the full
// YAML editor for anyone who needs a port/vendor hint/credential reference. Added 2026-09-12
// (user: simplify the common case, keep the full format reachable, not removed).
let inventoryMode = 'simple';

function setInventoryMode(mode) {
  inventoryMode = mode;
  document.getElementById('inventory-simple-wrap').style.display = mode === 'simple' ? 'block' : 'none';
  document.getElementById('inventory-advanced-wrap').style.display = mode === 'advanced' ? 'block' : 'none';
}

function syncInventoryFromSimpleList() {
  const lines = document.getElementById('inventory-simple').value
    .split('\\n').map(l => l.trim()).filter(l => l.length > 0);
  const yamlLines = ['targets:'];
  for (const host of lines) yamlLines.push(`  - host: ${host}`);
  document.getElementById('inventory').value = (lines.length ? yamlLines : ['targets: []']).join('\\n') + '\\n';
}

async function submitScan(confirmed) {
  if (inventoryMode === 'simple') syncInventoryFromSimpleList();
  const body = {
    policy: currentPolicy(),
    inventory_yaml: document.getElementById('inventory').value,
    confirmed: confirmed,
  };
  document.getElementById('run-btn').disabled = true;
  jobRunning = true;
  setLamps('running');
  const res = await fetch('/api/scan', {
    method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body),
  });
  const data = await res.json();
  document.getElementById('run-btn').disabled = false;

  if (!res.ok) {
    jobRunning = false;
    setLamps('trip');
    alert('Error: ' + (data.error || res.statusText));
    return;
  }
  if (data.requires_confirmation) {
    jobRunning = false;
    setLamps('idle');
    document.getElementById('confirm-box').style.display = 'block';
    const parts = [];
    if (data.destructive_checks && data.destructive_checks.length) {
      parts.push(`<p>${data.destructive_checks.length} <span class="destructive-tag" style="margin:0;">destructive</span> check(s) may fire (confirmed lockout risk, device write, or account creation).</p>`);
    }
    if (data.adverse_checks && data.adverse_checks.length) {
      parts.push(`<p>${data.adverse_checks.length} <span class="adverse-tag" style="margin:0;">adverse</span> check(s) may fire (plain login attempt, no known lockout risk).</p>`);
    }
    document.getElementById('confirm-details').innerHTML =
      parts.join('') + `<p>Against:</p><ul>${data.targets.map(t => `<li>${esc(t)}</li>`).join('')}</ul>`;
    return;
  }
  cancelConfirm();
  setLamps('running');
  pollJob(data.job_id);
}

function cancelConfirm() {
  document.getElementById('confirm-box').style.display = 'none';
}

async function pollJob(jobId) {
  document.getElementById('run-view').style.display = 'block';
  const statusEl = document.getElementById('job-status');
  const resultsEl = document.getElementById('results');
  while (true) {
    const res = await fetch('/api/jobs/' + jobId);
    const job = await res.json();
    statusEl.textContent = `job ${jobId}\\nstatus: ${job.status}\\nlog: ${job.log_path || '(pending)'}`;
    if (job.status === 'done' || job.status === 'error') {
      if (job.summary) {
        const s = job.summary;
        setLamps(s.confirmed > 0 ? 'trip' : 'healthy');
        let html = `<table><tr><th>Total</th><th>Confirmed</th><th>Fingerprint-only</th><th>Errors</th></tr>
          <tr><td>${esc(s.total)}</td><td class="status-confirmed">${esc(s.confirmed)}</td><td>${esc(s.fingerprint_only)}</td><td>${esc(s.errors)}</td></tr></table>`;

        if (job.log_path) {
          const ev = document.getElementById('include-evidence-toggle').checked ? '?include_evidence=1' : '';
          html += `<p>
            <a href="/api/jobs/${jobId}/log" download>Download raw JSONL log</a> &middot;
            <a href="/api/jobs/${jobId}/report.html${ev}" download>Download HTML report</a> &middot;
            <a href="/api/jobs/${jobId}/report.csv${ev}" download>Download CSV report</a>
          </p>`;
        }

        if (s.by_protocol && Object.keys(s.by_protocol).length) {
          html += '<h4>By Protocol</h4><table><tr><th>Protocol</th><th>Count</th></tr>';
          for (const [proto, count] of Object.entries(s.by_protocol)) {
            html += `<tr><td>${esc(proto)}</td><td>${esc(count)}</td></tr>`;
          }
          html += '</table>';
        }

        const confirmedFindings = (s.findings || []).filter(f => f.status === 'confirmed');
        if (confirmedFindings.length) {
          html += '<h4>Confirmed findings (triage)</h4><table><tr><th>Check</th><th>CVE/CAN</th><th>Severity</th><th>Confidence</th><th>Protocol</th><th>Target</th><th>Description</th></tr>';
          for (const f of confirmedFindings) {
            const cve = f.cve_id || f.can_id || 'n/a';
            html += `<tr><td>${esc(f.check_id)}</td><td>${esc(cve)}</td><td>${esc(f.severity_band)}</td><td>${esc(f.confidence)}</td><td>${esc(f.protocol)}</td><td>${esc(f.target)}</td><td>${esc(f.description)}</td></tr>`;
          }
          html += '</table>';
        }

        if (s.by_confidence && Object.keys(s.by_confidence).length) {
          html += '<h4>Confirmed-finding Confidence Breakdown</h4><table><tr><th>Confidence</th><th>Count</th></tr>';
          for (const [level, count] of Object.entries(s.by_confidence)) {
            html += `<tr><td>${esc(level)}</td><td>${esc(count)}</td></tr>`;
          }
          html += '</table>';
        }

        if (s.by_severity && Object.keys(s.by_severity).length) {
          html += '<h4>Confirmed-finding Severity Breakdown</h4><table><tr><th>Severity</th><th>Count</th></tr>';
          for (const [band, count] of Object.entries(s.by_severity)) {
            html += `<tr><td>${esc(band)}</td><td>${esc(count)}</td></tr>`;
          }
          html += '</table>';
        }

        resultsEl.innerHTML = html;
      } else if (job.error) {
        setLamps('trip');
        resultsEl.innerHTML = `<p class="status-confirmed">${esc(job.error)}</p>`;
      }
      jobRunning = false;
      return;
    }
    await new Promise(r => setTimeout(r, 1000));
  }
}

/* ── Discovery tab ─────────────────────────────────────────────────── */
function setDiscoveryMode(mode) {
  document.getElementById('mode-btn-active').classList.toggle('active', mode === 'active');
  document.getElementById('mode-btn-passive').classList.toggle('active', mode === 'passive');
  document.getElementById('mode-btn-sniff').classList.toggle('active', mode === 'sniff');
  document.getElementById('discovery-active-fields').style.display = mode === 'active' ? 'block' : 'none';
  document.getElementById('discovery-passive-fields').style.display = mode === 'passive' ? 'block' : 'none';
  document.getElementById('discovery-sniff-fields').style.display = mode === 'sniff' ? 'block' : 'none';
}

function onSniffSourceChange() {
  const src = document.getElementById('disc-sniff-source').value;
  document.getElementById('disc-sniff-span-fields').style.display = src === 'span' ? 'block' : 'none';
  document.getElementById('disc-sniff-pcap-fields').style.display = src === 'pcap' ? 'block' : 'none';
  document.getElementById('disc-sniff-zeek-fields').style.display = src === 'zeek_logs' ? 'block' : 'none';
}

async function loadDiscoveryListeners() {
  const res = await fetch('/api/discover-listeners');
  const data = await res.json();
  document.getElementById('discovery-protocol-list').innerHTML = (data.protocols || []).map(p =>
    `<label><input type="checkbox" id="discovery-protocol-cb-${esc(p)}" class="discovery-proto-cb" value="${esc(p)}" checked> ${esc(p)}</label>`
  ).join('') || '<i>No passive listeners registered.</i>';
}

function currentDiscoveryMode() {
  if (document.getElementById('mode-btn-sniff').classList.contains('active')) return 'sniff';
  if (document.getElementById('mode-btn-passive').classList.contains('active')) return 'passive';
  return 'active';
}

let discProbesLoaded = false;
async function loadDiscoveryProbes() {
  if (discProbesLoaded) return;
  discProbesLoaded = true;
  try {
    const res = await fetch('/api/discover-probes');
    const data = await res.json();
    const list = document.getElementById('disc-probe-list');
    list.innerHTML = '';
    const notes = data.notes || {};
    (data.probes || []).forEach(p => {
      const note = notes[p];
      const wrap = document.createElement('label');
      wrap.style.cssText = 'display:inline-flex; align-items:center; gap:4px; margin:0';
      wrap.innerHTML = '<input type="checkbox" class="disc-probe-cb" value="' + p + '" checked> ' + p +
        (note ? ' <span style="cursor:help; color:#b58900" title="' + note.replace(/"/g, '&quot;') + '">ⓘ</span>' : '');
      list.appendChild(wrap);
      if (note) {
        // Operator note shown while this probe is selected (e.g. ROC unit/group addressing default).
        const n = document.createElement('div');
        n.style.cssText = 'flex-basis:100%; font-size:11px; color:#888; margin:2px 0 6px 20px';
        n.textContent = note;
        const cb = wrap.querySelector('.disc-probe-cb');
        const sync = () => { n.style.display = cb.checked ? 'block' : 'none'; };
        cb.addEventListener('change', sync); sync();
        list.appendChild(n);
      }
    });
  } catch (e) {
    document.getElementById('disc-probe-list').textContent = 'failed to load probe list';
  }
}

function onDiscoveryMethodChange() {
  const method = document.getElementById('disc-method').value;
  document.getElementById('disc-iface-row').style.display = method === 'arp' ? 'block' : 'none';
  document.getElementById('disc-mqtt-fields').style.display = method === 'mqtt' ? 'block' : 'none';
  document.getElementById('disc-probe-fields').style.display = method === 'protocol_probe' ? 'block' : 'none';
  if (method === 'protocol_probe') loadDiscoveryProbes();
}

function showDiscErr(msg) {
  const el = document.getElementById('discovery-error');
  if (!el) { alert(msg); return; }
  el.textContent = msg;
  el.style.display = 'block';
}
function clearDiscErr() {
  const el = document.getElementById('discovery-error');
  if (el) el.style.display = 'none';
}

async function startDiscovery() {
  clearDiscErr();
  const mode = currentDiscoveryMode();
  let body = { mode };
  if (mode === 'active') {
    body.method = document.getElementById('disc-method').value;
    body.cidr = document.getElementById('disc-cidr').value.trim();
    body.iface = document.getElementById('disc-iface').value.trim() || null;
    body.timeout = parseFloat(document.getElementById('disc-timeout').value || '2');
    body.force = document.getElementById('disc-force').checked;
    if (body.method === 'mqtt') {
      body.port = parseInt(document.getElementById('disc-mqtt-port').value || '1883', 10);
      body.auto_sparkplug = document.getElementById('disc-mqtt-sparkplug').checked;
    }
    if (body.method === 'protocol_probe') {
      body.probes = Array.from(document.querySelectorAll('.disc-probe-cb:checked')).map(c => c.value);
    }
    if (!body.cidr) { showDiscErr('Enter a subnet in CIDR form, e.g. 192.168.1.0/24.'); return; }
  } else if (mode === 'sniff') {
    body.source = document.getElementById('disc-sniff-source').value;
    body.cve = document.getElementById('disc-sniff-cve').checked;
    body.detections = document.getElementById('disc-sniff-detections').checked;
    if (body.source === 'pcap') {
      const fi = document.getElementById('disc-sniff-pcap-file');
      const file = fi && fi.files && fi.files[0];
      if (file) {
        const se = document.getElementById('discovery-status');
        if (se) se.textContent = `Uploading ${file.name} (${(file.size/1048576).toFixed(1)} MB)…`;
        try {
          const up = await fetch('/api/upload-pcap', {method:'POST', headers:{'X-Filename': file.name}, body: file});
          const uj = await up.json();
          if (!up.ok) { showDiscErr('Upload failed: ' + (uj.error || up.status)); return; }
          body.pcap = uj.path;
        } catch (e) { showDiscErr('Upload failed: ' + e); return; }
      } else {
        body.pcap = document.getElementById('disc-sniff-pcap').value.trim();
        if (!body.pcap) { showDiscErr('Choose a capture to upload, or enter a server-side path.'); return; }
      }
    } else if (body.source === 'zeek_logs') {
      body.zeek_logs = document.getElementById('disc-sniff-zeek').value.trim();
      if (!body.zeek_logs) { showDiscErr('Enter the Zeek log directory on the server.'); return; }
    } else {
      body.iface = document.getElementById('disc-sniff-iface').value.trim() || null;
      body.window = parseFloat(document.getElementById('disc-sniff-window').value || '60');
    }
  } else {
    body.duration = parseFloat(document.getElementById('disc-duration').value || '30');
    body.iface = document.getElementById('disc-iface-passive').value.trim() || null;
    body.protocols = [...document.querySelectorAll('.discovery-proto-cb:checked')].map(cb => cb.value);
    if (body.protocols.includes('sparkplug_b')) {
      const host = document.getElementById('disc-broker-host').value.trim();
      const port = document.getElementById('disc-broker-port').value;
      if (host) {
        body.sparkplug_broker = { host, port: parseInt(port || '1883', 10) };
      }
    }
  }

  document.getElementById('discover-btn').disabled = true;
  jobRunning = true;
  setLamps('running');
  const res = await fetch('/api/discover', {
    method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body),
  });
  const data = await res.json();
  document.getElementById('discover-btn').disabled = false;
  if (!res.ok) {
    jobRunning = false;
    setLamps('trip');
    alert('Error: ' + (data.error || res.statusText));
    return;
  }
  pollDiscoveryJob(data.job_id);
}

async function pollDiscoveryJob(jobId) {
  const panel = document.getElementById('discovery-results-panel');
  const statusEl = document.getElementById('discovery-status');
  const throbber = document.getElementById('discovery-throbber');
  panel.style.display = 'block';
  if (throbber) throbber.className = 'throbber on';
  while (true) {
    const res = await fetch('/api/discover-jobs/' + jobId);
    const job = await res.json();
    const idle = job.idle_s || 0;
    // Throbber: amber + "no update" hint once a running job has gone quiet for a while, so a
    // long-running capture is visibly distinct from a hung one (it keeps spinning, with context).
    const stalled = job.status === 'running' && idle > 15;
    if (throbber) throbber.className = (job.status === 'running' ? 'throbber on' + (stalled ? ' stalled' : '') : 'throbber');
    statusEl.textContent = `job ${jobId} — status: ${job.status}`;
    // Live/partial streaming: render what's found so far while the capture is still running.
    if (job.status === 'running') {
      if (job.devices && job.devices.length) {
        lastDiscoveryDevices = job.devices;
        renderDiscoveryTable(job.devices);
        renderDiscoveryDetections(job.detections || null);
      }
      const found = (job.devices || []).length;
      statusEl.textContent = stalled
        ? `job ${jobId} — still working, no new activity for ${Math.round(idle)}s (long capture or stalled) — ${found} device(s) so far`
        : `job ${jobId} — capturing… ${found} device(s) so far`;
    }
    if (job.status === 'done' || job.status === 'error') {
      if (throbber) throbber.className = 'throbber';
      if (job.status === 'done') {
        setLamps(job.devices.length > 0 ? 'healthy' : 'idle');
        lastDiscoveryDevices = job.devices;
        renderDiscoveryTable(job.devices);
        renderDiscoveryFindings(job.findings || []);
        renderDiscoveryDetections(job.detections || null);
        statusEl.textContent = `${job.devices.length} device(s) found.`;
        const dl = document.getElementById('discovery-downloads');
        if (dl) {
          dl.innerHTML = job.devices.length
            ? `<a href="/api/discover-jobs/${jobId}/report.html" download>Download HTML report</a> &middot; ` +
              `<a href="/api/discover-jobs/${jobId}/report.csv" download>Download CSV</a>`
            : '';
        }
      } else {
        setLamps('trip');
        statusEl.textContent = 'Discovery failed: ' + job.error;
      }
      jobRunning = false;
      return;
    }
    await new Promise(r => setTimeout(r, 1000));
  }
}

function discoveryIdentityCell(d) {
  // Sparkplug B's `ip` is the MQTT BROKER's address, not the discovered edge device's own —
  // Sparkplug has no device-level IP at all, only a logical group/edge-node/device identity
  // carried in its topic namespace (core/discovery.py's own extra dict). Showing the broker IP
  // as if it were "the device" is actively misleading, so this method gets its own identity
  // rendering: the real logical identity as the primary label, broker address demoted to a
  // secondary "via" line. Every other discovery method's `ip` IS the device's own address, so
  // they're unaffected.
  const extra = d.extra || {};
  if (d.method === 'sparkplug_b') {
    const parts = [extra.group_id, extra.edge_node_id, extra.device_id].filter(Boolean);
    const label = parts.length ? parts.map(esc).join(' / ') : esc(d.ip);
    const broker = extra.broker || d.ip;
    return `${label}<span class="discovery-identity-sub">via broker ${esc(broker)}</span>`;
  }
  return esc(d.ip);
}

function renderDiscoveryTable(devices) {
  document.getElementById('discovery-tbody').innerHTML = devices.map((d, i) => {
    const extra = d.extra || {};
    const model = (extra.model && extra.model !== 'unknown') ? esc(extra.model) : '&mdash;';
    const cves = (extra.matched_cves || []).map(esc).join(', ') || '&mdash;';
    return `
    <tr data-ip="${esc(d.ip || '')}">
      <td><input type="checkbox" class="discovery-row-cb" data-index="${i}" checked></td>
      <td>${discoveryIdentityCell(d)}</td>
      <td>${d.mac ? esc(d.mac) : '&mdash;'}</td>
      <td>${esc(d.vendor)}</td>
      <td>${model}</td>
      <td><span class="method-dot ${esc(d.method)}"></span>${esc(d.method)}</td>
      <td>${cves}</td>
      <td>${esc(d.first_seen)}</td>
      <td>${esc(d.last_seen)}</td>
    </tr>`; }).join('') || '<tr><td colspan="9"><i>No devices found in this window.</i></td></tr>';
}

function renderDiscoveryFindings(findings) {
  const panel = document.getElementById('discovery-findings');
  if (!findings.length) { panel.style.display = 'none'; return; }
  panel.style.display = 'block';
  const modelHits = findings.filter(f => f.scope === 'model').length;
  document.getElementById('discovery-findings-note').textContent =
    `${modelHits} model-confirmed, ${findings.length - modelHits} vendor-wide — identity-only, no firmware/version gating.`;
  document.getElementById('discovery-findings-tbody').innerHTML = findings.map(f => `
    <tr>
      <td>${esc(f.ip)}</td>
      <td>${esc(f.vendor)} / ${esc(f.model || '')}</td>
      <td>${f.cve_id ? esc(f.cve_id) : '&mdash;'}</td>
      <td>${esc(f.candidate || '')}</td>
      <td>${esc(f.scope || '')}</td>
    </tr>`).join('');
}

function renderDiscoveryDetections(summary) {
  const panel = document.getElementById('discovery-detections');
  if (!summary || !summary.total) { panel.style.display = 'none'; return; }
  panel.style.display = 'block';
  const bm = summary.by_mode || {};
  const tech = Object.entries(summary.by_mitre || {}).map(([k, v]) => `${esc(k)} (${v})`).join(', ');
  const win = summary.first_ts ? `${esc(summary.first_ts)} .. ${esc(summary.last_ts)}` : '';
  document.getElementById('discovery-detections-note').innerHTML =
    `${summary.total} detection(s): ${bm.broad || 0} broad (exploitation-class), ${bm.narrow || 0} narrow (recon)` +
    (tech ? ` &middot; ${tech}` : '') + (win ? ` &middot; ${win}` : '') +
    `<br><em>Observed activity &mdash; traffic matching a check's signature, NOT a confirmed compromise. Correlate with source/asset context before acting.</em>`;
  const bft = summary.by_finding_type || {};
  const ftLine = Object.keys(bft).length
    ? ` &middot; finding types: ${Object.entries(bft).map(([k,v]) => `${esc(k)} (${v})`).join(', ')}` : '';
  document.getElementById('discovery-detections-note').innerHTML += ftLine;
  document.getElementById('discovery-detections-tbody').innerHTML = (summary.targets || []).map(t => {
    const modes = (t.modes || []).join(' ');
    const fts = (t.finding_types || []).join(' ');
    const dstCell = t.dst && t.dst.indexOf('.') >= 0 && t.dst.indexOf('255.255') < 0
      ? `<a href="#" onclick="highlightDevice('${esc(t.dst)}');return false;" title="Show this host in the inventory">${esc(t.dst)}</a>`
      : esc(t.dst);
    return `
    <tr class="det-row" data-modes="${esc(modes)}" data-ft="${esc(fts)}" data-text="${esc((t.dst + ' ' + (t.checks||[]).join(' ') + ' ' + (t.techniques||[]).join(' ')).toLowerCase())}">
      <td>${dstCell}${t.identity ? ' <span class="mono-note">[' + esc(t.identity) + ']</span>' : ''}</td>
      <td>${esc((t.modes || []).join('/'))}</td>
      <td>${esc((t.techniques || []).join(', ')) || '&mdash;'}</td>
      <td>${t.count}</td>
      <td>${esc((t.checks || []).join(', '))}</td>
    </tr>`; }).join('');
  filterDetections();
}

function filterDetections() {
  const q = (document.getElementById('det-filter-text')?.value || '').trim().toLowerCase();
  const mode = document.getElementById('det-filter-mode')?.value || '';
  let shown = 0;
  document.querySelectorAll('#discovery-detections-tbody tr.det-row').forEach(tr => {
    const okText = !q || (tr.dataset.text || '').includes(q);
    const okMode = !mode || (tr.dataset.modes || '').split(' ').includes(mode)
                          || (tr.dataset.ft || '').split(' ').includes(mode);
    const show = okText && okMode;
    tr.style.display = show ? '' : 'none';
    if (show) shown++;
  });
  const c = document.getElementById('det-filter-count');
  if (c) c.textContent = shown + ' shown';
}

function highlightDevice(ip) {
  const row = document.querySelector(`#discovery-tbody tr[data-ip="${CSS.escape(ip)}"]`);
  if (!row) return;
  row.scrollIntoView({behavior: 'smooth', block: 'center'});
  row.classList.add('row-flash');
  setTimeout(() => row.classList.remove('row-flash'), 1800);
}

function toggleAllDiscoveryRows(checked) {
  document.querySelectorAll('.discovery-row-cb').forEach(cb => cb.checked = checked);
}

function copySelectedToScanner() {
  const indices = [...document.querySelectorAll('.discovery-row-cb:checked')].map(cb => parseInt(cb.dataset.index, 10));
  const selected = indices.map(i => lastDiscoveryDevices[i]);
  if (!selected.length) { showDiscErr('Select at least one discovered device first.'); return; }
  const lines = ['targets:'];
  for (const d of selected) {
    if (d.method === 'sparkplug_b') {
      const extra = d.extra || {};
      const parts = [extra.group_id, extra.edge_node_id, extra.device_id].filter(Boolean);
      if (parts.length) lines.push(`  # Sparkplug B identity: ${parts.join(' / ')} (host below is the MQTT broker, not this edge device's own address)`);
    }
    lines.push(`  - host: ${d.ip}`);
    if (d.vendor && d.vendor !== 'unknown') lines.push(`    vendor: ${d.vendor}`);
  }
  document.getElementById('inventory').value = lines.join('\\n') + '\\n';
  setInventoryMode('advanced'); // discovered-device hints (vendor, etc.) can't be expressed by the simple list
  switchTab('scanner');
}

function emitDiscoveryTargets() {
  const devs = lastDiscoveryDevices || [];
  if (!devs.length) { showDiscErr('No discovered devices to emit yet.'); return; }
  const lines = ['# Pre-hinted targets from passive discovery (zero transmit). Review before any active scan.',
                 'targets:'];
  for (const d of devs) {
    if (!d.ip) continue;
    const extra = d.extra || {};
    lines.push(`  - host: ${d.ip}`);
    if (d.vendor && d.vendor !== 'unknown') lines.push(`    vendor: "${d.vendor}"`);
    if (extra.model && extra.model !== 'unknown') lines.push(`    product: "${extra.model}"`);
    if (extra.firmware && extra.firmware !== 'unknown') lines.push(`    version: "${extra.firmware}"`);
  }
  const blob = new Blob([lines.join('\\n') + '\\n'], {type: 'text/yaml'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'passive-targets.yaml';
  a.click();
  URL.revokeObjectURL(a.href);
}

loadChecks();
loadDiscoveryListeners();
loadFieldRef();
loadCredentials();
loadNotAutomatable();
startHeartbeat();
applyDensity(localStorage.getItem('icsscanner-density-laptop') === '1');
</script>
</body>
</html>
"""
