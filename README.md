# Server-Side Request Forgery (SSRF) protection plugin for HTTPlug

[![Build Status](https://travis-ci.org/j0k3r/httplug-ssrf-plugin.svg?branch=master)](https://travis-ci.org/j0k3r/httplug-ssrf-plugin)
[![Code Coverage](https://scrutinizer-ci.com/g/j0k3r/httplug-ssrf-plugin/badges/coverage.png?b=master)](https://scrutinizer-ci.com/g/j0k3r/httplug-ssrf-plugin/?branch=master)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/j0k3r/httplug-ssrf-plugin/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/j0k3r/httplug-ssrf-plugin/?branch=master)

Inspired from [SafeCurl](https://github.com/j0k3r/safecurl), it intends to validate each part of the URL against a white or black list, to help protect against _Server-Side Request Forgery_ attacks when using [HTTPlug](http://docs.php-http.org/en/latest/).

Each part of the URL is broken down and validated against a white or black list. This includes resolve a domain name to it's IP addresses.

## Installation

It can be included in any PHP project using [Composer](https://getcomposer.org).

```
composer require j0k3r/httplug-ssrf-plugin
```

## Usage

```php
use Graby\HttpClient\Plugin\ServerSideRequestForgeryProtection\ServerSideRequestForgeryProtectionPlugin;
use Http\Client\Common\PluginClient;
use Http\Discovery\HttpClientDiscovery;

$ssrfPlugin = new ServerSideRequestForgeryProtectionPlugin();

$pluginClient = new PluginClient(
    HttpClientDiscovery::find(),
    [$ssrfPlugin]
);
```

The plugin throws a `Graby\HttpClient\Plugin\ServerSideRequestForgeryProtection\Exception\InvalidURLException` if the url is not valid.

#### Options

The default options are to not allow access to any [private IP addresses](http://en.wikipedia.org/wiki/Private_network), and to only allow HTTP(S) connections.

If you wish to add your own options (such as to blacklist any requests to domains your control), simply get a new `Graby\HttpClient\Plugin\ServerSideRequestForgeryProtection\Options` object, add to the white or black lists, and pass it along with the method calls.

Domains are express using regex syntax, whilst IPs, scheme and ports are standard strings (IPs can be specified in [CIDR notation](https://en.wikipedia.org/wiki/Cidr)).

```php
use Graby\HttpClient\Plugin\ServerSideRequestForgeryProtection\Options;
use Graby\HttpClient\Plugin\ServerSideRequestForgeryProtection\ServerSideRequestForgeryProtectionPlugin;
use Http\Discovery\HttpClientDiscovery;
use Http\Discovery\MessageFactoryDiscovery;
use Http\Client\Common\PluginClient;

$options = new Options();
$options->addToList('blacklist', 'domain', '(.*)\.example\.com');

$pluginClient = new PluginClient(
    HttpClientDiscovery::find(),
    [new ServerSideRequestForgeryProtectionPlugin($options)]
);

// This will throw an Graby\HttpClient\Plugin\ServerSideRequestForgeryProtection\Exception\InvalidURLException\InvalidDomainException
$request = MessageFactoryDiscovery::find()->createRequest('GET', 'http://www.example.com');
$response = $pluginClient->sendRequest($request);

$options = new Options();
$options->setList('whitelist', ['scheme' => ['https']]);

$pluginClient = new PluginClient(
    HttpClientDiscovery::find(),
    [new ServerSideRequestForgeryProtectionPlugin($options)]
);

// This will be allowed, and return the response
$request = MessageFactoryDiscovery::find()->createRequest('GET', 'https://www.example.com');
$response = $pluginClient->sendRequest($request);

// This will throw an Graby\HttpClient\Plugin\ServerSideRequestForgeryProtection\Exception\InvalidURLException\InvalidDomainException
$request = MessageFactoryDiscovery::find()->createRequest('GET', 'http://www.example.com');
$response = $pluginClient->sendRequest($request);
```

#### Optional Protections

In addition to the standard checks, two more are available.

The first is to prevent [DNS Rebinding](https://en.wikipedia.org/wiki/DNS_rebinding) attacks. This can be enabled by calling the `enablePinDns` method on an `Options` object. There is one major issue with this - the SSL certificate **can't** be validated. This is due to the real hostname being sent in the `Host` header, and the URL using the IP address.

```php
$options = new Options();
$options->enablePinDns();
```

The second disables the use of credentials in a URL, since PHP's `parse_url` returns values which differ from ones cURL uses. This is a temporary fix.

```php
use Graby\HttpClient\Plugin\ServerSideRequestForgeryProtection\Options;
use Graby\HttpClient\Plugin\ServerSideRequestForgeryProtection\ServerSideRequestForgeryProtectionPlugin;
use Http\Discovery\HttpClientDiscovery;
use Http\Discovery\MessageFactoryDiscovery;
use Http\Client\Common\PluginClient;

$options = new Options();
$options->disableSendCredentials();

//This will throw an Http\Client\Exception\RequestException
$pluginClient = new PluginClient(
    HttpClientDiscovery::find(),
    [new ServerSideRequestForgeryProtectionPlugin($options)]
);
$request = MessageFactoryDiscovery::find()->createRequest('GET', 'http://user:pass@google.com');
$response = $pluginClient->sendRequest($request);
```

#### Cavets

Since the libray uses [`gethostbynamel`](http://php.net/manual/en/function.gethostbynamel.php) to resolve domain names, which isn't IPv6 compatible, the class will only work with IPv4 at the moment.
