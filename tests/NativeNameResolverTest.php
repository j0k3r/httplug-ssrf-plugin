<?php

namespace Tests\Graby\HttpClient\Plugin\ServerSideRequestForgeryProtection;

use Graby\HttpClient\Plugin\ServerSideRequestForgeryProtection\NativeNameResolver;
use PHPUnit\Framework\TestCase;

class NativeNameResolverTest extends TestCase
{
    /**
     * @return iterable<array{string, string}>
     */
    public static function numericHosts(): iterable
    {
        yield ['127.0.0.1', '127.0.0.1'];
        yield ['0177.1', '127.0.0.1'];
        yield ['2130706433', '127.0.0.1'];
        yield ['0x7f000001', '127.0.0.1'];
        yield ['::1', '::1'];
        yield ['[::1]', '::1'];
        yield ['[0:0:0:0:0:0:0:1]', '::1'];
        yield ['[2606:4700:4700::1111]', '2606:4700:4700::1111'];
    }

    /**
     * @dataProvider numericHosts
     */
    public function testResolvesNumericHostsWithoutDns(string $host, string $expected): void
    {
        $this->assertSame([$expected], (new NativeNameResolver())->resolve($host));
    }

    public function testResolvesLocalhostThroughTheSystemResolver(): void
    {
        $ips = (new NativeNameResolver())->resolve('localhost');

        $this->assertNotEmpty($ips);
        $this->assertSame(array_values(array_unique($ips)), $ips);
        foreach ($ips as $ip) {
            $this->assertContains($ip, ['127.0.0.1', '::1']);
        }
    }
}
