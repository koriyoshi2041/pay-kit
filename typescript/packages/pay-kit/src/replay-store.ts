import type { Store } from 'mppx';

/** Replay store capability required by x402's reserve-before-settle lifecycle. */
export interface ReservingReplayStore extends Store.Store {
    reserve(key: string, value?: unknown, ttlSeconds?: number): Promise<boolean>;
}

/** Whether a store provides an atomic reserve operation. */
export function isReservingReplayStore(store: Store.Store): store is ReservingReplayStore {
    return typeof (store as Partial<ReservingReplayStore>).reserve === 'function';
}

/** Atomic replay-store contract required by MPP server construction. */
export type ReplayStore = Store.Store & {
    readonly isDurable?: boolean;
    readonly isShared?: boolean;
    putIfAbsent(key: string, value: unknown): Promise<boolean>;
};

/** Narrow the legacy Store.Store surface to the atomic MPP replay contract. */
export function isAtomicReplayStore(store: Store.Store): store is ReplayStore {
    return 'putIfAbsent' in store && typeof store.putIfAbsent === 'function';
}

export function isProductionReplayStore(store: ReplayStore): boolean {
    return store.isShared === true || store.isDurable === true;
}

type MemoryReplayStore = ReplayStore & ReservingReplayStore;

/**
 * Process-local atomic replay store for local development and explicit insecure
 * off-localnet opt-in. Share the returned instance between handlers when they
 * run in one process; production replicas should inject a durable implementation
 * whose `reserve` and `putIfAbsent` map to datastore-native compare-and-set.
 */
export function createMemoryReplayStore(): MemoryReplayStore {
    const entries = new Map<string, { expiresAt?: number; value: unknown }>();

    function live(key: string): { expiresAt?: number; value: unknown } | undefined {
        const entry = entries.get(key);
        if (entry?.expiresAt !== undefined && entry.expiresAt <= Date.now()) {
            entries.delete(key);
            return undefined;
        }
        return entry;
    }

    return {
        delete(key: string): Promise<void> {
            entries.delete(key);
            return Promise.resolve();
        },
        get(key: string) {
            return Promise.resolve(live(key)?.value ?? null);
        },
        isDurable: false,
        isShared: false,
        put(key: string, value: unknown): Promise<void> {
            entries.set(key, { value });
            return Promise.resolve();
        },
        putIfAbsent(key: string, value: unknown): Promise<boolean> {
            if (live(key) !== undefined) return Promise.resolve(false);
            entries.set(key, { value });
            return Promise.resolve(true);
        },
        reserve(key: string, value: unknown = true, ttlSeconds?: number): Promise<boolean> {
            if (live(key) !== undefined) return Promise.resolve(false);
            entries.set(key, {
                expiresAt: ttlSeconds === undefined ? undefined : Date.now() + ttlSeconds * 1000,
                value,
            });
            return Promise.resolve(true);
        },
    };
}

/** Explicit alias used when MPP opts into process-local development storage. */
export function createUnsafeMemoryReplayStore(): MemoryReplayStore {
    return createMemoryReplayStore();
}

function isConsumedReplayKey(key: string): boolean {
    return key.startsWith('solana-charge:consumed:') || key.startsWith('solana-subscription:consumed:');
}

/**
 * Adapt pay-kit's atomic store to the upstream get/put Store surface.
 *
 * #211 already serializes charge verification inside one process. This view
 * leaves that lock untouched and upgrades only the final consumed-marker write
 * to a cross-instance atomic reservation.
 */
export function atomicReplayStoreView(store: ReplayStore): Store.Store {
    return {
        delete: key => store.delete(key),
        get: key => store.get(key),
        async put(key, value) {
            if (isConsumedReplayKey(key)) {
                if (!(await store.putIfAbsent(key, value))) {
                    throw new Error('MPP replay key is already reserved');
                }
                return;
            }
            await store.put(key, value);
        },
    };
}
