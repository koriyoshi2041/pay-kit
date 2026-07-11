import { describe, expect, it } from 'vitest';
import type { Store } from 'mppx';

import { configure, configureFromEnv } from '../config.js';
import { ConfigurationError, DemoSignerOnMainnetError, ProtocolNotSupportedError } from '../errors.js';
import type { ReplayStore, ReservingReplayStore } from '../replay-store.js';
import { Signer } from '../signer.js';

const SECRET = { mpp: { challengeBindingSecret: 'test-secret', allowUnsafeMemoryStore: true } };
const values = new Map<string, unknown>();
const SHARED_STORE: ReplayStore & ReservingReplayStore = {
    isShared: true,
    async delete(key) {
        values.delete(key);
    },
    async get(key) {
        return (values.get(key) ?? null) as never;
    },
    async put(key, value) {
        values.set(key, value);
    },
    async putIfAbsent(key, value) {
        if (values.has(key)) return false;
        values.set(key, value);
        return true;
    },
    async reserve(key, value = true) {
        if (values.has(key)) return false;
        values.set(key, value);
        return true;
    },
};
const LEGACY_STORE: Store.Store = {
    async delete() {},
    async get() {
        return null;
    },
    async put() {},
};
const X402_STORE: Store.Store & { reserve(key: string, value?: unknown, ttlSeconds?: number): Promise<boolean> } = {
    ...LEGACY_STORE,
    async reserve() {
        return true;
    },
};

describe('configure', () => {
    it('applies the canonical defaults', async () => {
        const config = await configure(SECRET);
        expect(config.network).toBe('solana_localnet');
        expect(config.accept).toEqual(['mpp']);
        expect(config.stablecoins).toEqual(['USDC']);
        expect(config.mpp.expiresIn).toBe(120);
        expect(config.mpp.realm).toBe('App');
        expect(config.operator.feePayer).toBe(true);
        expect(config.operator.signer.isDemo).toBe(true);
        expect(config.operator.recipient).toBe(config.operator.signer.pubkey);
        expect(config.rpcUrl).toBe('http://localhost:8899');
        expect(config.x402).toEqual({});
    });

    it('refuses the demo signer on mainnet', async () => {
        await expect(configure({ ...SECRET, network: 'solana_mainnet' })).rejects.toThrow(DemoSignerOnMainnetError);
        const signer = await Signer.generate();
        const config = await configure({
            ...SECRET,
            network: 'solana_mainnet',
            operator: { signer },
            replayStore: SHARED_STORE,
        });
        expect(config.operator.recipient).toBe(signer.pubkey);
    });

    it('accepts the shipped protocols (mpp + x402)', async () => {
        const config = await configure({ ...SECRET, accept: ['x402', 'mpp'] });
        expect(config.accept).toEqual(['x402', 'mpp']);
    });

    it('does not require the MPP putIfAbsent capability for x402-only config', async () => {
        const config = await configure({ accept: ['x402'], replayStore: X402_STORE });
        expect(config.accept).toEqual(['x402']);
        expect(config.replayStore).toBe(X402_STORE);
    });

    it('fails closed at runtime for a legacy non-atomic MPP store', async () => {
        await expect(configure({ ...SECRET, replayStore: LEGACY_STORE })).rejects.toThrow(/atomic putIfAbsent/);
    });

    it('rejects protocols this SDK does not ship', async () => {
        await expect(configure({ ...SECRET, accept: ['stripe' as never] })).rejects.toThrow(ProtocolNotSupportedError);
        await expect(configure({ ...SECRET, accept: [] })).rejects.toThrow(ConfigurationError);
    });

    it('validates stablecoins and expiry', async () => {
        await expect(configure({ ...SECRET, stablecoins: ['DOGE' as never] })).rejects.toThrow(ConfigurationError);
        await expect(configure({ ...SECRET, mpp: { ...SECRET.mpp, expiresIn: -1 } })).rejects.toThrow(
            ConfigurationError,
        );
    });

    it('requires a challenge secret outside localnet', async () => {
        const signer = await Signer.generate();
        delete process.env.PAY_KIT_MPP_SECRET;
        delete process.env.MPP_SECRET_KEY;
        await expect(configure({ network: 'solana_devnet', operator: { signer } })).rejects.toThrow(ConfigurationError);
        process.env.MPP_SECRET_KEY = 'env-secret';
        const config = await configure({ network: 'solana_devnet', operator: { signer }, replayStore: SHARED_STORE });
        expect(config.mpp.challengeBindingSecret).toBe('env-secret');
        delete process.env.MPP_SECRET_KEY;
    });

    it('requires an injected replay store outside localnet', async () => {
        const signer = await Signer.generate();
        await expect(
            configure({
                ...SECRET,
                mpp: { challengeBindingSecret: 'test-secret' },
                network: 'solana_devnet',
                operator: { signer },
            }),
        ).rejects.toThrow(/atomic shared replayStore/);

        const local = await configure(SECRET);
        expect(local.replayStore).toBeDefined();

        const production = await configure({
            ...SECRET,
            network: 'solana_devnet',
            operator: { signer },
            replayStore: SHARED_STORE,
        });
        expect(production.replayStore).toBe(SHARED_STORE);
    });

    it('honors the explicit in-memory replay-store environment opt-in', async () => {
        process.env.PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE = '1';
        try {
            const config = await configure({
                mpp: { challengeBindingSecret: 'test-secret' },
                network: 'solana_devnet',
                operator: { signer: await Signer.generate() },
            });
            expect(config.mpp.allowUnsafeMemoryStore).toBe(true);
            expect(config.replayStore).toBeDefined();
        } finally {
            delete process.env.PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE;
        }
    });

    it('lets an explicit false override the in-memory replay-store environment opt-in', async () => {
        process.env.PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE = '1';
        try {
            await expect(
                configure({
                    mpp: { allowUnsafeMemoryStore: false, challengeBindingSecret: 'test-secret' },
                    network: 'solana_devnet',
                    operator: { signer: await Signer.generate() },
                }),
            ).rejects.toThrow(/atomic shared replayStore/);
        } finally {
            delete process.env.PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE;
        }
    });

    it('configures from prefixed environment variables', async () => {
        process.env.PAY_KIT_NETWORK = 'solana_devnet';
        process.env.PAY_KIT_MPP_SECRET = 'env-secret';
        process.env.PAY_KIT_MPP_EXPIRES_IN = '60';
        process.env.PAY_KIT_STABLECOINS = '';
        process.env.PAY_KIT_RPC_URL = 'http://rpc.example';
        process.env.PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE = '1';
        try {
            const config = await configureFromEnv('PAY_KIT_', SHARED_STORE);
            expect(config.network).toBe('solana_devnet');
            expect(config.mpp.challengeBindingSecret).toBe('env-secret');
            expect(config.mpp.expiresIn).toBe(60);
            expect(config.rpcUrl).toBe('http://rpc.example');
            expect(config.x402).toEqual({});
        } finally {
            delete process.env.PAY_KIT_NETWORK;
            delete process.env.PAY_KIT_MPP_SECRET;
            delete process.env.PAY_KIT_MPP_EXPIRES_IN;
            delete process.env.PAY_KIT_STABLECOINS;
            delete process.env.PAY_KIT_RPC_URL;
            delete process.env.PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE;
        }
    });
});
