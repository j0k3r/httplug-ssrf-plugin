<?php

namespace Tests\Graby\HttpClient\Plugin\ServerSideRequestForgeryProtection;

use Graby\HttpClient\Plugin\ServerSideRequestForgeryProtection\Exception\InvalidURLException\InvalidDomainException;
use Graby\HttpClient\Plugin\ServerSideRequestForgeryProtection\Exception\InvalidURLException\InvalidIPException;
use Graby\HttpClient\Plugin\ServerSideRequestForgeryProtection\Options;
use Graby\HttpClient\Plugin\ServerSideRequestForgeryProtection\Url;
use PHPUnit\Framework\TestCase;

class UrlSecurityTest extends TestCase
{
    /**
     * @return iterable<string, array{string}>
     */
    public static function blockedAddresses(): iterable
    {
        yield 'IPv4 loopback' => ['127.0.0.1'];
        yield 'IPv4 private' => ['10.0.0.1'];
        yield 'IPv4 metadata' => ['169.254.169.254'];
        yield 'IPv4 CGNAT' => ['100.64.0.1'];
        yield 'IPv4 multicast' => ['224.0.0.1'];
        yield 'unspecified' => ['::'];
        yield 'loopback' => ['::1'];
        yield 'expanded loopback' => ['0:0:0:0:0:0:0:1'];
        yield 'IPv4-compatible loopback' => ['::127.0.0.1'];
        yield 'IPv4-mapped loopback' => ['::ffff:127.0.0.1'];
        yield 'IPv4-mapped public IP' => ['::ffff:8.8.8.8'];
        yield 'NAT64 loopback' => ['64:ff9b::7f00:1'];
        yield 'local-use NAT64' => ['64:ff9b:1::7f00:1'];
        yield 'discard-only' => ['100::1'];
        yield 'dummy prefix' => ['100:0:0:1::1'];
        yield 'Teredo' => ['2001::1'];
        yield 'benchmarking' => ['2001:2::1'];
        yield 'documentation' => ['2001:db8::1'];
        yield '6to4 loopback' => ['2002:7f00:1::'];
        yield 'documentation RFC 9637' => ['3fff::1'];
        yield 'segment routing' => ['5f00::1'];
        yield 'unique local fc00' => ['fc00::1'];
        yield 'unique local fd00' => ['fd00::1'];
        yield 'cloud metadata' => ['fd00:ec2::254'];
        yield 'uppercase unique local' => ['FD00::1'];
        yield 'link local' => ['fe80::1'];
        yield 'link-local upper boundary' => ['febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff'];
        yield 'deprecated site local' => ['fec0::1'];
        yield 'multicast' => ['ff02::1'];
    }

    /**
     * @dataProvider blockedAddresses
     */
    public function testRejectsEveryUnsafeAnswer(string $ip): void
    {
        foreach ([['1.1.1.1', $ip], [$ip, '1.1.1.1']] as $ips) {
            $resolver = new MockNameResolver(['mixed.example' => $ips]);

            try {
                Url::validateUrl('https://mixed.example/', new Options(), $resolver);
                $this->fail('An unsafe DNS answer was accepted: ' . $ip);
            } catch (InvalidIPException $e) {
                $this->assertStringContainsString('blacklisted', $e->getMessage());
            }
        }
    }

    public function testAcceptsPublicDualStackAnswers(): void
    {
        $ips = ['1.1.1.1', '2606:4700:4700::1111'];
        $resolver = new MockNameResolver(['public.example' => $ips]);
        $result = Url::validateUrl('https://public.example:8080/path?query=1', new Options(), $resolver);

        $this->assertSame($ips, $result['ips']);
        $this->assertSame('https://public.example:8080/path?query=1', $result['url']);
    }

    public function testAcceptsAnIpv6OnlyDomain(): void
    {
        $resolver = new MockNameResolver(['public.example' => ['2606:4700:4700::1111']]);
        $result = Url::validateUrl('https://public.example/', new Options(), $resolver);

        $this->assertSame(['2606:4700:4700::1111'], $result['ips']);
    }

    public function testAcceptsAPublicIpv6Literal(): void
    {
        $result = Url::validateUrl('https://[2606:4700:4700::1111]:8080/path', new Options());

        $this->assertSame('https://[2606:4700:4700::1111]:8080/path', $result['url']);
        $this->assertSame(['2606:4700:4700::1111'], $result['ips']);
    }

    public function testRejectsAPrivateIpv6Literal(): void
    {
        $this->expectException(InvalidIPException::class);

        Url::validateUrl('http://[::1]/', new Options());
    }

    public function testBuildsAValidIpv6UrlWithPinningEnabled(): void
    {
        $options = new Options();
        $options->enablePinDns();
        $resolver = new MockNameResolver(['public.example' => '2606:4700:4700::1111']);
        $result = Url::validateUrl('https://public.example:8080/path', $options, $resolver);

        $this->assertSame('https://[2606:4700:4700::1111]:8080/path', $result['url']);
        $this->assertSame('public.example', $result['host']);
    }

    public function testEveryAnswerMustMatchTheAllowlist(): void
    {
        $options = new Options();
        $options->addToList(Options::LIST_WHITELIST, Options::TYPE_IP, '1.1.1.1');

        foreach ([['1.1.1.1', '8.8.8.8'], ['8.8.8.8', '1.1.1.1'], ['1.1.1.1', '2606:4700:4700::1111']] as $ips) {
            try {
                Url::validateHost('public.example', $options, new MockNameResolver(['public.example' => $ips]));
                $this->fail('An address outside the allowlist was accepted');
            } catch (InvalidIPException $e) {
                $this->assertStringContainsString('whitelisted', $e->getMessage());
            }
        }
    }

    public function testAcceptsAnswersCoveredByDifferentAllowlistEntries(): void
    {
        $options = new Options();
        $options->setList(Options::LIST_WHITELIST, ['1.1.1.1', '2606:4700::/32'], Options::TYPE_IP);
        $ips = ['1.1.1.1', '2606:4700:4700::1111'];
        $result = Url::validateHost('public.example', $options, new MockNameResolver(['public.example' => $ips]));

        $this->assertSame($ips, $result['ips']);
    }

    public function testBlocklistStillAppliesToAllowlistedAddresses(): void
    {
        $options = new Options();
        $options->addToList(Options::LIST_WHITELIST, Options::TYPE_IP, '::1');
        $this->expectException(InvalidIPException::class);
        $this->expectExceptionMessage('blacklisted');

        Url::validateUrl('http://[::1]/', $options);
    }

    public function testRejectsAnUnresolvedHost(): void
    {
        $this->expectException(InvalidDomainException::class);

        Url::validateHost('unresolved.example', new Options(), new MockNameResolver([]));
    }

    public function testRejectsInvalidResolverOutputEvenWithoutABlocklist(): void
    {
        $options = new Options();
        $options->setList(Options::LIST_BLACKLIST, [], Options::TYPE_IP);
        $this->expectException(InvalidIPException::class);

        Url::validateHost('invalid.example', $options, new MockNameResolver(['invalid.example' => 'not-an-ip']));
    }

    /**
     * @return iterable<array{string, string, bool}>
     */
    public static function cidrCases(): iterable
    {
        yield ['1.1.1.1', '1.1.1.1', true];
        yield ['1.1.1.1', '8.8.8.8', false];
        yield ['10.255.255.255', '10.0.0.0/8', true];
        yield ['11.0.0.0', '10.0.0.0/8', false];
        yield ['172.31.255.255', '172.16.0.0/12', true];
        yield ['172.32.0.0', '172.16.0.0/12', false];
        yield ['1.1.1.1', '0.0.0.0/0', true];
        yield ['1.1.1.1', '1.1.1.1/32', true];
        yield ['1.1.1.2', '1.1.1.1/32', false];
        yield ['1.1.1.1', '1.1.1.255/24', true];
        yield ['2606:4700:4700::1111', '2606:4700:4700:0:0:0:0:1111', true];
        yield ['2606:4700:4700::1111', '2606:4700::/32', true];
        yield ['2606:4700:4700::1111', '::/0', true];
        yield ['2606:4700:4700::1111', '2606:4700:4700::1111/128', true];
        yield ['2606:4700:4700::1112', '2606:4700:4700::1111/128', false];
        yield ['fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff', 'fc00::/7', true];
        yield ['fe00::', 'fc00::/7', false];
        yield ['2001:db8:0:0:7fff::', '2001:db8::/65', true];
        yield ['2001:db8:0:0:8000::', '2001:db8::/65', false];
        yield ['2001:db8::3', '2001:db8::2/127', true];
        yield ['2001:db8::4', '2001:db8::2/127', false];
        yield ['::1', '0.0.0.0/0', false];
        yield ['1.1.1.1', '::/0', false];
        yield ['::ffff:127.0.0.1', '::ffff:0:0/96', true];
        yield ['not-an-ip', '0.0.0.0/0', false];
        yield ['1.1.1.1', 'not-a-subnet/24', false];
        yield ['1.1.1.1', '0.0.0.0/-1', false];
        yield ['1.1.1.1', '0.0.0.0/33', false];
        yield ['::1', '::/129', false];
        yield ['::1', '::/invalid', false];
        yield ['::1', '::/', false];
    }

    /**
     * @dataProvider cidrCases
     */
    public function testCidrMatch(string $ip, string $cidr, bool $expected): void
    {
        $this->assertSame($expected, Url::cidrMatch($ip, $cidr));
    }
}
