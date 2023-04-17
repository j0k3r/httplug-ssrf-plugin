<?php

declare(strict_types=1);

namespace Tests\Graby\HttpClient\Plugin\ServerSideRequestForgeryProtection;

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

class ServerSideRequestForgeryProtectionPluginTest extends \PHPUnit\Framework\TestCase
{
    public function testGet(): void
    {
        $mockHandler = new MockHandler([
            new Response(200),
        ]);
        $mockClient = new Client([
            'handler' => HandlerStack::create($mockHandler),
        ]);
        $client = new PluginClient($mockClient, [new ServerSideRequestForgeryProtectionPlugin()]);

        $response = $client->sendRequest(new Request('GET', 'http://www.google.com'));

        $this->assertNotEmpty($response);
        $this->assertSame(200, $response->getStatusCode());
    }

    /**
     * @return array<array{string, string}>
     */
    public function dataForBlockedUrl(): array
    {
        return [
            ['http://0.0.0.0:123', 'Provided port "123" doesn\'t match whitelisted values: 80, 443, 8080'],
            ['http://127.0.0.1/server-status', 'Provided host "127.0.0.1" resolves to "127.0.0.1", which matches a blacklisted value: 127.0.0.0/8'],
            // Obfuscating IPv4
            ['http://0177.1/server-status', 'Provided host "0177.1" resolves to "127.0.0.1", which matches a blacklisted value: 127.0.0.0/8'],
            ['file:///etc/passwd', 'Provided URL "file:///etc/passwd" doesn\'t contain a hostname'],
            ['ssh://localhost', 'Provided scheme "ssh" doesn\'t match whitelisted values: http, https'],
            ['gopher://localhost', 'Provided scheme "gopher" doesn\'t match whitelisted values: http, https'],
            ['telnet://localhost:25', 'Provided scheme "telnet" doesn\'t match whitelisted values: http, https'],
            ['http://169.254.169.254/latest/meta-data/', 'Provided host "169.254.169.254" resolves to "169.254.169.254", which matches a blacklisted value: 169.254.0.0/16'],
            ['ftp://myhost.com', 'Provided scheme "ftp" doesn\'t match whitelisted values: http, https'],
            ['http://user:pass@safecurl.fin1te.net?@google.com/', 'Credentials passed in but "sendCredentials" is set to false'],
        ];
    }

    /**
     * @dataProvider dataForBlockedUrl
     */
    public function testBlockedUrl(string $url, string $message): void
    {
        $this->expectException(RequestException::class);
        $this->expectExceptionMessage($message);

        $mockHandler = new MockHandler([
            new Response(200),
        ]);
        $mockClient = new Client([
            'handler' => HandlerStack::create($mockHandler),
        ]);
        $client = new PluginClient($mockClient, [new ServerSideRequestForgeryProtectionPlugin()]);

        $client->sendRequest(new Request('GET', $url));
    }

    /**
     * @return array<array{string, string}>
     */
    public function dataForBlockedUrlByOptions(): array
    {
        return [
            ['http://login:password@google.fr', 'Credentials passed in but "sendCredentials" is set to false'],
            ['http://safecurl.fin1te.net', 'Provided host "safecurl.fin1te.net" matches a blacklisted value'],
        ];
    }

    /**
     * @dataProvider dataForBlockedUrlByOptions
     */
    public function testBlockedUrlByOptions(string $url, string $message): void
    {
        $this->expectException(RequestException::class);
        $this->expectExceptionMessage($message);

        $options = new Options();
        $options->addToList(Options::LIST_BLACKLIST, 'domain', '(.*)\.fin1te\.net');
        $options->addToList(Options::LIST_WHITELIST, 'scheme', 'ftp');
        $options->disableSendCredentials();

        $mockHandler = new MockHandler([
            new Response(200),
        ]);
        $mockClient = new Client([
            'handler' => HandlerStack::create($mockHandler),
        ]);
        $client = new PluginClient($mockClient, [new ServerSideRequestForgeryProtectionPlugin($options)]);

        $client->sendRequest(new Request('GET', $url));
    }

    public function testWithPinDnsEnabled(): void
    {
        $options = new Options();
        $options->enablePinDns();

        $mockHandler = new MockHandler([
            new Response(200),
        ]);
        $mockClient = new Client([
            'handler' => HandlerStack::create($mockHandler),
        ]);
        $client = new PluginClient($mockClient, [new ServerSideRequestForgeryProtectionPlugin($options)]);

        $response = $client->sendRequest(new Request('GET', 'http://google.com'));

        $this->assertNotEmpty($response);
    }

    public function testWithFollowLocationLeadingToABlockedUrl(): void
    {
        $this->expectException(RequestException::class);
        $this->expectExceptionMessage('Provided port "123" doesn\'t match whitelisted values: 80, 443, 8080');

        $options = new Options();
        $mockHandler = new MockHandler([
            new Response(301, ['Location' => 'http://0.0.0.0:123/']),
            new Response(200),
        ]);
        $mockClient = new Client([
            'handler' => HandlerStack::create($mockHandler),
        ]);
        $client = new PluginClient($mockClient, [
            new ServerSideRequestForgeryProtectionPlugin($options),
            new RedirectPlugin(),
        ]);

        $client->sendRequest(new Request('GET', 'http://google.com'));
    }

    public function testAsyncGet(): void
    {
        $mockHandler = new MockHandler([
            new Response(200),
        ]);
        $mockClient = new Client([
            'handler' => HandlerStack::create($mockHandler),
        ]);
        $client = new PluginClient($mockClient, [new ServerSideRequestForgeryProtectionPlugin()]);

        $promise = $client->sendAsyncRequest(new Request('GET', 'http://www.google.com'))->then(
            function ($response) {
                $this->assertNotEmpty($response);
                $this->assertSame(200, $response->getStatusCode());

                // HTTPPlug requires that Response is always returned.
                return $response;
            }
        )->wait();
    }

    public function testAsyncBlocked(): void
    {
        $url = 'http://0.0.0.0:123';
        $message = 'Provided port "123" doesn\'t match whitelisted values: 80, 443, 8080';

        $mockHandler = new MockHandler([
            new Response(200),
        ]);
        $mockClient = new Client([
            'handler' => HandlerStack::create($mockHandler),
        ]);
        $client = new PluginClient($mockClient, [new ServerSideRequestForgeryProtectionPlugin()]);

        $promise = $client->sendAsyncRequest(new Request('GET', $url));

        // The exception should only be thrown when calling `wait()`.
        $this->expectException(RequestException::class);
        $this->expectExceptionMessage($message);

        $promise->wait();
    }
}
