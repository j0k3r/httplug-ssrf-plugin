<?php

namespace Tests\Graby\HttpClient\Plugin\ServerSideRequestForgeryProtection;

use Graby\HttpClient\Plugin\ServerSideRequestForgeryProtection\Exception\InvalidURLException\InvalidIPException;
use Graby\HttpClient\Plugin\ServerSideRequestForgeryProtection\Options;
use Graby\HttpClient\Plugin\ServerSideRequestForgeryProtection\ServerSideRequestForgeryProtectionPlugin;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use Http\Client\Common\Plugin\RedirectPlugin;
use Http\Client\Common\PluginClient;
use Http\Client\Exception\RequestException;
use PHPUnit\Framework\TestCase;

class DualStackProtectionTest extends TestCase
{
    /**
     * @return iterable<array{list<string>, bool, bool}>
     */
    public static function mixedAnswers(): iterable
    {
        foreach ([['1.1.1.1', 'fd00::1'], ['fd00::1', '1.1.1.1']] as $ips) {
            foreach ([false, true] as $pinDns) {
                foreach ([false, true] as $async) {
                    yield [$ips, $pinDns, $async];
                }
            }
        }
    }

    /**
     * @dataProvider mixedAnswers
     *
     * @param list<string> $ips
     */
    public function testSnykScenarioIsRejectedBeforeSending(array $ips, bool $pinDns, bool $async): void
    {
        $options = new Options();
        if ($pinDns) {
            $options->enablePinDns();
        }
        $resolver = new MockNameResolver(['mixed.example' => $ips]);
        $handler = new MockHandler([new Response(200)]);
        $client = new PluginClient(
            new Client(['handler' => HandlerStack::create($handler)]),
            [new ServerSideRequestForgeryProtectionPlugin($options, null, $resolver)]
        );
        $request = new Request('GET', 'https://mixed.example/');

        try {
            if ($async) {
                $client->sendAsyncRequest($request)->wait();
            } else {
                $client->sendRequest($request);
            }
            $this->fail('The mixed public IPv4 / private IPv6 domain was accepted');
        } catch (RequestException $e) {
            $this->assertInstanceOf(InvalidIPException::class, $e->getPrevious());
            $this->assertNull($handler->getLastRequest());
        }
    }

    public function testRedirectToAMixedDomainIsRejected(): void
    {
        $resolver = new MockNameResolver([
            'public.example' => ['1.1.1.1', '2606:4700:4700::1111'],
            'mixed.example' => ['1.1.1.1', 'fd00::1'],
        ]);
        $handler = new MockHandler([
            new Response(302, ['Location' => 'https://mixed.example/private']),
            new Response(200),
        ]);
        $client = new PluginClient(
            new Client(['handler' => HandlerStack::create($handler)]),
            [new ServerSideRequestForgeryProtectionPlugin(null, null, $resolver), new RedirectPlugin()]
        );

        try {
            $client->sendRequest(new Request('GET', 'https://public.example/'));
            $this->fail('The redirect to a mixed public/private domain was followed');
        } catch (RequestException $e) {
            $this->assertInstanceOf(InvalidIPException::class, $e->getPrevious());
            $lastRequest = $handler->getLastRequest();
            $this->assertNotNull($lastRequest);
            $this->assertSame('https://public.example/', (string) $lastRequest->getUri());
            $this->assertCount(1, $handler);
        }
    }
}
