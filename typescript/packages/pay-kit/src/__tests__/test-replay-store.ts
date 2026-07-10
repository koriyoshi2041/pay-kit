import { createMemoryReplayStore } from '../replay-store.js';

/** Test-only stand-in for a datastore-backed atomic store shared by all handlers. */
export function createSharedReplayStore() {
    return { ...createMemoryReplayStore(), isShared: true as const };
}
