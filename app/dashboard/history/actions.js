// Showcase build: server actions are disabled because the site is exported
// as a fully static bundle (no Node runtime, no backend).
// Returns a benign noop so the client-side "Clear History" modal can still
// be exercised in the demo without throwing.

export async function clearUserHistoryAction() {
  await new Promise((resolve) => setTimeout(resolve, 300))
  return { ok: true, demo: true }
}
