<?php

namespace Graby\HttpClient\Plugin\ServerSideRequestForgeryProtection;

use Graby\HttpClient\Plugin\ServerSideRequestForgeryProtection\Exception\InvalidURLException;
use Http\Client\Common\Plugin;
use Http\Client\Exception\RequestException;
use Http\Discovery\UriFactoryDiscovery;
use Http\Message\UriFactory;
use Psr\Http\Message\RequestInterface;

/**
 * Validates each part of the URL against a white or black list, to help protect against Server-Side Request Forgery
 * attacks.
 *
 * @see https://github.com/j0k3r/safecurl
 * @see https://whitton.io/articles/safecurl-ssrf-protection-and-a-capture-the-bitcoins/
 */
class ServerSideRequestForgeryProtectionPlugin implements Plugin
{
    private $options;
    private $uriFactory;

    public function __construct(Options $options = null, UriFactory $uriFactory = null)
    {
        $this->options = $options ?: new Options();
        $this->uriFactory = $uriFactory ?: UriFactoryDiscovery::find();
    }

    /**
     * {@inheritdoc}
     *
     * @throws \Http\Client\Exception\RequestException
     */
    public function handleRequest(RequestInterface $request, callable $next, callable $first)
    {
        try {
            $urlData = Url::validateUrl((string) $request->getUri(), $this->options);
        } catch (InvalidURLException $e) {
            throw new RequestException($e->getMessage(), $request, $e);
        }

        $uri = $this->uriFactory->createUri($urlData['url']);

        if ((string) $uri !== (string) $request->getUri()) {
            $request = $request->withUri($uri->withHost($urlData['host']));
        }

        return $next($request);
    }
}
