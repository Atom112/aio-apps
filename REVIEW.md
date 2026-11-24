# Review checklist

Automated checks (CI) cover structure and style. A human reviewer covers intent and the
handful of things a linter cannot see. Work top-down; leave a comment for each `NO`.

## 1. Identity

- [ ] `id` belongs to the publisher (`io.<publisher>.*`), not a copy of another app.
- [ ] `name`/`description` describe what the app actually does (no "AI assistant" generic).
- [ ] `author`, `license`, `homepage` are real; homepage resolves to the same publisher.

## 2. Capabilities

- [ ] Every declared capability is used; nothing is declared "for later".
- [ ] `storage.kv` justified if the app is stateless by nature.
- [ ] No request for capabilities that are not implemented (the app would break silently).

## 3. Behaviour

- [ ] The app works without network access (v1 has no `net.fetch`).
- [ ] Empty / loading / error states exist and errors are text, not alerts.
- [ ] No hidden background work; the app renders only while open.
- [ ] Screenshots match the current build.

## 4. Style

- [ ] Uses `theme.css`; dark and light both readable.
- [ ] Panel apps stay within the host column; canvas apps keep the host header usable.
- [ ] Interactive elements are keyboard reachable.

## 5. Safety

- [ ] No attempt to embed remote content, frames or scripts.
- [ ] No prompts that trick users into pasting secrets into the app.
- [ ] Any telemetry is disclosed; the default is none.

## 6. Decision

- [ ] Approve with a signed-off commit message (`Reviewed-by: <name>`).
- [ ] Or request changes with the checklist item quoted.
