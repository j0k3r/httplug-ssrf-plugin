# Server-Side Request Forgery (SSRF) protection plugin for HTTPlug

![CI](https://github.com/j0k3r/httplug-ssrf-plugin/workflows/CI/badge.svg)
[![Coverage Status](https://coveralls.io/repos/j0k3r/httplug-ssrf-plugin/badge.svg?branch=master&service=github)](https://coveralls.io/github/j0k3r/httplug-ssrf-plugin?branch=master)

Inspired from [SafeCurl](https://github.com/j0k3r/safecurl), it intends to validate each part of the URL against a white or black list, to help protect against _Server-Side Request Forgery_ attacks when using [HTTPlug](https://docs.php-http.org/en/latest/).

Each part of the URL is broken down and validated against a white or black list. This includes resolve a domain name to it's IP addresses.

## Installation

Requires PHP 8.2 or later and the `sockets` extension (`ext-sockets`).

It can be included in any PHP project using [Composer](https://getcomposer.org).

```
composer require j0k3r/httplug-ssrf-plugin
```

## Usage

```php
use Graby\HttpClient\Plugin\ServerSideRequestForgeryProtection\ServerSideRequestForgeryProtectionPlugin;
use Http\Client\Common\PluginClient;
use Http\Discovery\Psr18ClientDiscovery;

$ssrfPlugin = new ServerSideRequestForgeryProtectionPlugin();

$pluginClient = new PluginClient(
    Psr18ClientDiscovery::find(),
    [$ssrfPlugin]
);
```

The plugin throws a `Graby\HttpClient\Plugin\ServerSideRequestForgeryProtection\Exception\InvalidURLException` if the url is not valid.

#### Options

The default options are to not allow access to any [private IP addresses](https://en.wikipedia.org/wiki/Private_network), and to only allow HTTP(S) connections.

If you wish to add your own options (such as to blacklist any requests to domains your control), simply get a new `Graby\HttpClient\Plugin\ServerSideRequestForgeryProtection\Options` object, add to the white or black lists, and pass it along with the method calls.

Domains are express using regex syntax, whilst IPs, scheme and ports are standard strings (IPv4 and IPv6 addresses can be specified in [CIDR notation](https://en.wikipedia.org/wiki/Cidr)).

Every address returned by the system resolver must pass the IP checks. If an IP whitelist is configured, every address must match at least one whitelist entry. A blacklist match always rejects the host, even if the address also matches the whitelist. This can reject hosts previously accepted because only one of their addresses matched the whitelist.

The default blacklist also rejects IPv6 private, loopback, link-local, multicast and special-purpose ranges, including IPv4-mapped, IPv4-compatible, NAT64, 6to4 and Teredo addresses.

```php
use Graby\HttpClient\Plugin\ServerSideRequestForgeryProtection\Options;
use Graby\HttpClient\Plugin\ServerSideRequestForgeryProtection\ServerSideRequestForgeryProtectionPlugin;
use Http\Discovery\Psr17FactoryDiscovery;
use Http\Discovery\Psr18ClientDiscovery;
use Http\Client\Common\PluginClient;

$options = new Options();
$options->addToList(Options::LIST_BLACKLIST, Options::TYPE_DOMAIN, '(.*)\.example\.com');

$pluginClient = new PluginClient(
    Psr18ClientDiscovery::find(),
    [new ServerSideRequestForgeryProtectionPlugin($options)]
);

// This will throw an Graby\HttpClient\Plugin\ServerSideRequestForgeryProtection\Exception\InvalidURLException\InvalidDomainException
$request = Psr17FactoryDiscovery::findRequestFactory()->createRequest('GET', 'https://www.example.com');
$response = $pluginClient->sendRequest($request);

$options = new Options();
$options->setList(Options::LIST_WHITELIST, [Options::TYPE_SCHEME => ['https']]);

$pluginClient = new PluginClient(
    Psr18ClientDiscovery::find(),
    [new ServerSideRequestForgeryProtectionPlugin($options)]
);

// This will be allowed, and return the response
$request = Psr17FactoryDiscovery::findRequestFactory()->createRequest('GET', 'https://www.example.com');
$response = $pluginClient->sendRequest($request);

// This will throw an Graby\HttpClient\Plugin\ServerSideRequestForgeryProtection\Exception\InvalidURLException\InvalidDomainException
$request = Psr17FactoryDiscovery::findRequestFactory()->createRequest('GET', 'https://www.example.com');
$response = $pluginClient->sendRequest($request);
```

#### Optional Protections

In addition to the standard checks, two more are available.

The legacy `enablePinDns` option attempts to prevent [DNS Rebinding](https://en.wikipedia.org/wiki/DNS_rebinding) by replacing the URL hostname with a validated IP. However, the plugin's subsequent hostname rewrite can undo that replacement; this is tracked separately in [#27](https://github.com/j0k3r/httplug-ssrf-plugin/pull/27). Do not rely on this option as a DNS-rebinding guarantee. Replacing the hostname with an IP also prevents normal HTTPS hostname verification. Do not disable certificate verification to work around this limitation.

```php
$options = new Options();
$options->enablePinDns();
```

The second disables the use of credentials in a URL, since PHP's `parse_url` returns values which differ from ones cURL uses. This is a temporary fix.

```php
use Graby\HttpClient\Plugin\ServerSideRequestForgeryProtection\Options;
use Graby\HttpClient\Plugin\ServerSideRequestForgeryProtection\ServerSideRequestForgeryProtectionPlugin;
use Http\Discovery\Psr17FactoryDiscovery;
use Http\Discovery\Psr18ClientDiscovery;
use Http\Client\Common\PluginClient;

$options = new Options();
$options->disableSendCredentials();

//This will throw an Http\Client\Exception\RequestException
$pluginClient = new PluginClient(
    Psr18ClientDiscovery::find(),
    [new ServerSideRequestForgeryProtectionPlugin($options)]
);
$request = Psr17FactoryDiscovery::findRequestFactory()->createRequest('GET', 'https://user:pass@google.com');
$response = $pluginClient->sendRequest($request);
```

#### Caveats

IPv4 and IPv6 addresses are resolved through the system resolver using [`socket_addrinfo_lookup`](https://www.php.net/manual/en/function.socket-addrinfo-lookup.php), including local hosts-file entries. A domain resolving to both a public IPv4 and a private IPv6 address is rejected.

These checks validate the addresses returned at validation time. A client can perform a new DNS lookup when connecting, so validation alone does not prevent DNS rebinding. Connection pinning requires support from the underlying HTTP transport.

Redirects must pass through this plugin as well (for example using HTTPlug's `RedirectPlugin`). Redirects followed internally by the underlying client bypass the plugin's checks.
