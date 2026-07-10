"""Fail-closed replay-store configuration for the Python x402 adapter."""

from __future__ import annotations

import pytest
from solders.keypair import Keypair

from solana_pay_kit import LocalSigner, MemoryStore, Operator, Protocol, configure
from solana_pay_kit._paycore.network import Network
from solana_pay_kit.config import reset
from solana_pay_kit.errors import ConfigurationError
from solana_pay_kit.protocols.x402 import X402Adapter


class _SharedMemoryStore(MemoryStore):
    is_shared = True


@pytest.fixture(autouse=True)
def _clean(monkeypatch: pytest.MonkeyPatch):
    reset()
    monkeypatch.setenv("PAY_KIT_DISABLE_PREFLIGHT", "1")
    monkeypatch.delenv("PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE", raising=False)
    yield
    reset()


def _config(network: Network):
    operator = Operator(
        signer=LocalSigner.from_keypair(Keypair()),
        recipient=str(Keypair().pubkey()),
    )
    return configure(
        network=network,
        preflight=False,
        accept=(Protocol.X402,),
        operator=operator,
    )


@pytest.mark.parametrize("network", [Network.SOLANA_DEVNET, Network.SOLANA_MAINNET])
def test_nonlocalnet_without_shared_replay_store_rejects(network: Network):
    with pytest.raises(ConfigurationError, match="requires an injected shared replay_store outside localnet"):
        X402Adapter(_config(network))


@pytest.mark.asyncio
async def test_nonlocalnet_accepts_injected_atomic_store():
    store = _SharedMemoryStore()
    adapter = X402Adapter(_config(Network.SOLANA_DEVNET), replay_store=store)

    assert adapter._store is store
    assert await adapter._store.put_if_absent("x402:test", True) is True
    assert await adapter._store.put_if_absent("x402:test", True) is False


def test_localnet_preserves_implicit_development_store():
    adapter = X402Adapter(_config(Network.SOLANA_LOCALNET))

    assert isinstance(adapter._store, MemoryStore)


def test_nonlocalnet_memory_store_requires_explicit_development_opt_in(monkeypatch: pytest.MonkeyPatch, caplog):
    monkeypatch.setenv("PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE", "1")

    adapter = X402Adapter(_config(Network.SOLANA_DEVNET))

    assert isinstance(adapter._store, MemoryStore)
    assert "process-local replay store outside localnet" in caplog.text
