// Process-local cache for recently fetched scan history pages.
//
// The app is local-first (Electron/Next.js), so the backing store does not
// need to be cross-process. A plain `Map` keyed by `<userId>:<pageSize>`
// gives us a cheap L1 cache in front of Supabase. Entries expire after a
// short TTL so revalidatePath() propagations still reach the UI quickly.

const DEFAULT_TTL_MS = 30 * 1000

class ScanCache {
  constructor(ttlMs = DEFAULT_TTL_MS) {
    this.ttlMs = ttlMs
    this.store = new Map()
  }

  _key(userId, pageSize) {
    return `${userId}:${pageSize}`
  }

  get(userId, pageSize) {
    const key = this._key(userId, pageSize)
    const entry = this.store.get(key)
    if (!entry) return null
    if (Date.now() - entry.savedAt > this.ttlMs) {
      this.store.delete(key)
      return null
    }
    return entry.value
  }

  set(userId, pageSize, value) {
    this.store.set(this._key(userId, pageSize), {
      value,
      savedAt: Date.now(),
    })
  }

  clear(userId) {
    if (!userId) {
      this.store.clear()
      return
    }
    for (const key of this.store.keys()) {
      if (key.startsWith(`${userId}:`)) this.store.delete(key)
    }
  }
}

export const scanCache = new ScanCache()
