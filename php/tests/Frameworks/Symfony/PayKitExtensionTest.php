<?php

declare(strict_types=1);

namespace PayKit\Tests\Frameworks\Symfony;

use PayKit\Frameworks\Symfony\DependencyInjection\PayKitExtension;
use PayKit\Protocols\Mpp\Adapter;
use PayKit\Store\FileStore;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;

final class PayKitExtensionTest extends TestCase
{
    public function testProductionMppBootWiresConfiguredReplayStoreService(): void
    {
        $container = new ContainerBuilder();
        $directory = sys_get_temp_dir() . '/pay-kit-symfony-' . bin2hex(random_bytes(8));
        $container->register('app.mpp_replay_store', FileStore::class)
            ->setArgument('$directory', $directory)
            ->setPublic(true);
        $container->register('paykit.psr_http_factory', \stdClass::class)->setPublic(true);
        $container->register('paykit.http_foundation_factory', \stdClass::class)->setPublic(true);
        (new PayKitExtension())->load([[
            'network' => 'solana_devnet',
            'accept' => ['mpp'],
            'mpp_challenge_binding_secret' => 'test-secret-0123456789abcdef-0123456789',
            'mpp_replay_store_service' => 'app.mpp_replay_store',
            'preflight' => false,
        ]], $container);

        $store = $container->getDefinition(Adapter::class)->getArgument('$replayStore');
        self::assertInstanceOf(Reference::class, $store);
        self::assertSame('app.mpp_replay_store', (string) $store);
        $container->compile();
        self::assertInstanceOf(Adapter::class, $container->get(Adapter::class));
    }

    public function testX402OnlyBootDoesNotRegisterMppAdapter(): void
    {
        $container = new ContainerBuilder();
        (new PayKitExtension())->load([[
            'network' => 'solana_devnet',
            'accept' => ['x402'],
        ]], $container);

        self::assertFalse($container->hasDefinition(Adapter::class));
    }
}
