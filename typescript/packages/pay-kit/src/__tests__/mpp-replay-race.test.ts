import { beforeEach, describe, expect, it, vi } from 'vitest';

const captured = vi.hoisted(() => ({ charge: [] as any[], subscription: [] as any[] }));

vi.mock('@solana/mpp/server', () => ({
    Mppx: {
        create: () => ({
            charge: () => async () => ({
                challenge: new Response(null, { headers: { 'www-authenticate': 'Payment test' }, status: 402 }),
                status: 402,
            }),
            subscription: () => async () => ({
                challenge: new Response(null, { headers: { 'www-authenticate': 'Payment test' }, status: 402 }),
                status: 402,
            }),
        }),
    },
    solana: {
        charge: (options: any) => {
            captured.charge.push(options.store);
            return options;
        },
        subscription: (options: any) => {
            captured.subscription.push(options.store);
            return options;
        },
    },
}));

import { createMppAdapter } from '../adapters/mpp.js';
import { configure } from '../config.js';
import { Gate } from '../gate.js';
import { usd } from '../price.js';
import type { ReplayStore } from '../replay-store.js';
import { Signer } from '../signer.js';

const SELLER = 'AyNAa2VPe2t5pgg8M61iE6kqMudkV98zsT4rkAZuU6tj';
const PULLER = 'CXG3Pq3DwZb1HVckhPQbVxiwoNGM3jNGYvC2BSdkj1pK';

function sharedStore(): ReplayStore {
    const values = new Map<string, unknown>();
    return {
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
    };
}

describe('MPP replay-store adapter wiring', () => {
    beforeEach(() => {
        captured.charge.length = 0;
        captured.subscription.length = 0;
    });

    it('atomically reserves charge markers across two independent adapters', async () => {
        const replayStore = sharedStore();
        const config = await configure({
            mpp: { challengeBindingSecret: 'race-test-secret' },
            operator: { recipient: SELLER, signer: await Signer.generate() },
            replayStore,
        });
        const gate = Gate.create(
            { amount: usd('1.00'), name: 'charge', payTo: SELLER },
            { accept: ['mpp'], payTo: SELLER },
        );
        const adapters = [createMppAdapter(config), createMppAdapter(config)];
        await Promise.all(adapters.map(adapter => adapter.challengeHeaders(gate, new Request('http://test/charge'))));

        const results = await Promise.allSettled(
            captured.charge.map(store => store.put('solana-charge:consumed:signature', true)),
        );
        expect(results.map(result => result.status).sort()).toEqual(['fulfilled', 'rejected']);
    });

    it('forwards the atomic replay store into subscription construction', async () => {
        const config = await configure({
            mpp: { challengeBindingSecret: 'subscription-store-test' },
            operator: { recipient: SELLER, signer: await Signer.generate() },
            replayStore: sharedStore(),
        });
        const gate = Gate.create(
            {
                amount: usd('1.00'),
                kind: 'subscription',
                name: 'plan',
                payTo: SELLER,
                subscription: { periodCount: 1, periodUnit: 'day', planId: 'plan-1', puller: PULLER },
            },
            { accept: ['mpp'], payTo: SELLER },
        );
        await createMppAdapter(config).challengeHeaders(gate, new Request('http://test/subscription'));
        expect(captured.subscription).toHaveLength(1);
        await expect(captured.subscription[0].put('solana-subscription:consumed:id', true)).resolves.toBeUndefined();
        await expect(captured.subscription[0].put('solana-subscription:consumed:id', true)).rejects.toMatchObject({
            message: expect.stringContaining('MPP replay key is already reserved'),
            name: 'VerificationFailedError',
        });
    });
});
