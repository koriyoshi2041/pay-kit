import type { Store } from 'mppx';

/** Atomic replay-store contract required by MPP server construction. */
export type ReplayStore = Store.Store & {
    readonly isDurable?: boolean;
    readonly isShared?: boolean;
    putIfAbsent(key: string, value: unknown): Promise<boolean>;
};

/** Narrow the legacy Store.Store surface to the atomic replay contract. */
export function isAtomicReplayStore(store: Store.Store): store is ReplayStore {
    return 'putIfAbsent' in store && typeof store.putIfAbsent === 'function';
}

export function isProductionReplayStore(store: ReplayStore): boolean {
    return store.isShared === true || store.isDurable === true;
}

/** Explicit process-local store used only behind the unsafe development flag. */
export function createUnsafeMemoryReplayStore(): ReplayStore {
    const values = new Map<string, unknown>();
    return {
        delete(key) {
            values.delete(key);
            return Promise.resolve();
        },
        get(key) {
            return Promise.resolve((values.get(key) ?? null) as never);
        },
        isDurable: false,
        isShared: false,
        put(key, value) {
            values.set(key, value);
            return Promise.resolve();
        },
        putIfAbsent(key, value) {
            if (values.has(key)) return Promise.resolve(false);
            values.set(key, value);
            return Promise.resolve(true);
        },
    };
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
