# GeekNosy UI system

Derived from the product brief, the assigned industrial permit-to-work direction, and UI/UX Pro Max guidance for data-dense operational dashboards.

## Visual contract

- **Mode:** light, designed for long audit sessions and legible evidence review.
- **Structure:** familiar application rail, work area and data table. The permit world contributes typography, palette, density and one authorization-rail interaction; it does not replace standard controls.
- **Primary palette:** ink `#142033`, paper `#F4F2EC`, surface `#FFFEFA`, rule `#C9C5BA`.
- **Action:** safety orange `#E6531F`; hover `#BD3810`.
- **States:** verified `#177253`, warning `#9B6500`, danger `#B7272F`, focus `#1D66C2`.
- **Typography:** Archivo Variable for display and headings; IBM Plex Sans Variable for body and UI. Monospace is reserved for URLs, hashes and code evidence.

## Density and spacing

- Base space: 4px. Common gaps: 8, 12, 16, 20, 24, 32px.
- Desktop rail: 232px. Header on mobile: 68px.
- Inputs: at least 43px high. Table rows: 44–52px.
- Cards use 0–12px radii; operational panels stay square or lightly rounded. One elevation mechanism per surface.

## Interaction

- Focus indicators use a 3px blue outline with 3:1 state contrast and remain unobscured.
- Hover never changes layout. Transitions run 150–200ms with an ease-out curve.
- Reduced-motion removes nonessential movement.
- Every action has loading, disabled, error and empty behavior.
- Destructive actions require confirmation; authorization and active checks require separate attestations.

## Content

- Spanish-first, precise and calm.
- Controls name the action. Errors state the problem and recovery.
- Severity always appears as text plus color.
- Findings describe observed evidence and confidence; they never claim exploitability without validation.

## Avoid

- Neon cyber styling, glass decoration, generic blue-purple gradients or terminal cosplay.
- Icon/heading/text tile grids as page structure.
- Decorative monospaced text, Unicode icons and emoji.
- Hidden advanced risk, unlabeled fields or color-only status.
