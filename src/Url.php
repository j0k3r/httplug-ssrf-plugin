<?php

namespace Graby\HttpClient\Plugin\ServerSideRequestForgeryProtection;

use Graby\HttpClient\Plugin\ServerSideRequestForgeryProtection\Exception\InvalidURLException;
use Graby\HttpClient\Plugin\ServerSideRequestForgeryProtection\Exception\InvalidURLException\InvalidDomainException;
use Graby\HttpClient\Plugin\ServerSideRequestForgeryProtection\Exception\InvalidURLException\InvalidIPException;
use Graby\HttpClient\Plugin\ServerSideRequestForgeryProtection\Exception\InvalidURLException\InvalidPortException;
use Graby\HttpClient\Plugin\ServerSideRequestForgeryProtection\Exception\InvalidURLException\InvalidSchemeException;

class Url
{
    /**
     * Validates the whole URL.
     *
     * @param string  $url
     * @param Options $options
     *
     * @throws InvalidURLException
     *
     * @return array
     */
    public static function validateUrl($url, Options $options)
    {
        if ('' === trim($url)) {
            throw new InvalidURLException('Provided URL "' . $url . '" cannot be empty');
        }

        //Split URL into parts first
        $parts = parse_url($url);

        if (empty($parts)) {
            throw new InvalidURLException('Error parsing URL "' . $url . '"');
        }

        if (!array_key_exists('host', $parts)) {
            throw new InvalidURLException('Provided URL "' . $url . '" doesn\'t contain a hostname');
        }

        //If credentials are passed in, but we don't want them, raise an exception
        if (!$options->getSendCredentials() && (array_key_exists('user', $parts) || array_key_exists('pass', $parts))) {
            throw new InvalidURLException('Credentials passed in but "sendCredentials" is set to false');
        }

        $parts['scheme'] = array_key_exists('scheme', $parts) ? self::validateScheme($parts['scheme'], $options) : 'http';

        //Validate the port
        if (array_key_exists('port', $parts)) {
            $parts['port'] = self::validatePort($parts['port'], $options);
        }

        //Validate the host
        $host = self::validateHost($parts['host'], $options);
        $parts['host'] = $host['host'];
        if ($options->getPinDns()) {
            //Since we're pinning DNS, we replace the host in the URL
            //with an IP, then get cURL to send the Host header
            $parts['host'] = $host['ips'][0];
        }

        //Rebuild the URL
        $url = self::buildUrl($parts);

        return [
            'url' => $url,
            'host' => $host['host'],
            'ips' => $host['ips'],
        ];
    }

    /**
     * Validates a URL scheme.
     *
     * @param string  $scheme
     * @param Options $options
     *
     * @throws InvalidSchemeException
     *
     * @return string
     */
    public static function validateScheme($scheme, Options $options)
    {
        $scheme = strtolower($scheme);

        //Whitelist always takes precedence over a blacklist
        if (!$options->isInList('whitelist', 'scheme', $scheme)) {
            throw new InvalidSchemeException('Provided scheme "' . $scheme . '" doesn\'t match whitelisted values: ' . implode(', ', $options->getList('whitelist', 'scheme')));
        }

        if ($options->isInList('blacklist', 'scheme', $scheme)) {
            throw new InvalidSchemeException('Provided scheme "' . $scheme . '" matches a blacklisted value');
        }

        //Existing value is fine
        return $scheme;
    }

    /**
     * Validates a port.
     *
     * @param string|int $port
     * @param Options    $options
     *
     * @throws InvalidPortException
     *
     * @return string
     */
    public static function validatePort($port, Options $options)
    {
        $port = (string) $port;
        if (!$options->isInList('whitelist', 'port', $port)) {
            throw new InvalidPortException('Provided port "' . $port . '" doesn\'t match whitelisted values: ' . implode(', ', $options->getList('whitelist', 'port')));
        }

        if ($options->isInList('blacklist', 'port', $port)) {
            throw new InvalidPortException('Provided port "' . $port . '" matches a blacklisted value');
        }

        //Existing value is fine
        return $port;
    }

    /**
     * Validates a URL host.
     *
     * @param string  $host
     * @param Options $options
     *
     * @throws InvalidDomainException
     * @throws InvalidIPException
     *
     * @return array
     */
    public static function validateHost($host, Options $options)
    {
        $host = strtolower($host);

        //Check the host against the domain lists
        if (!$options->isInList('whitelist', 'domain', $host)) {
            throw new InvalidDomainException('Provided host "' . $host . '" doesn\'t match whitelisted values: ' . implode(', ', $options->getList('whitelist', 'domain')));
        }

        if ($options->isInList('blacklist', 'domain', $host)) {
            throw new InvalidDomainException('Provided host "' . $host . '" matches a blacklisted value');
        }

        //Now resolve to an IP and check against the IP lists
        $ips = @gethostbynamel($host);
        if (empty($ips)) {
            throw new InvalidDomainException('Provided host "' . $host . '" doesn\'t resolve to an IP address');
        }

        $whitelistedIps = $options->getList('whitelist', 'ip');

        if (!empty($whitelistedIps)) {
            $valid = false;

            foreach ($whitelistedIps as $whitelistedIp) {
                foreach ($ips as $ip) {
                    if (self::cidrMatch($ip, $whitelistedIp)) {
                        $valid = true;
                        break 2;
                    }
                }
            }

            if (!$valid) {
                throw new InvalidIpException('Provided host "' . $host . '" resolves to "' . implode(', ', $ips) . '", which doesn\'t match whitelisted values: ' . implode(', ', $whitelistedIps));
            }
        }

        $blacklistedIps = $options->getList('blacklist', 'ip');

        if (!empty($blacklistedIps)) {
            foreach ($blacklistedIps as $blacklistedIp) {
                foreach ($ips as $ip) {
                    if (self::cidrMatch($ip, $blacklistedIp)) {
                        throw new InvalidIpException('Provided host "' . $host . '" resolves to "' . implode(', ', $ips) . '", which matches a blacklisted value: ' . $blacklistedIp);
                    }
                }
            }
        }

        return [
            'host' => $host,
            'ips' => $ips,
        ];
    }

    /**
     * Re-build a URL based on an array of parts.
     *
     * @param array $parts
     *
     * @return string
     */
    public static function buildUrl($parts)
    {
        $url = '';

        $url .= !empty($parts['scheme']) ? $parts['scheme'] . '://' : '';
        $url .= !empty($parts['user']) ? $parts['user'] : '';
        $url .= !empty($parts['pass']) ? ':' . $parts['pass'] : '';
        //If we have a user or pass, make sure to add an "@"
        $url .= !empty($parts['user']) || !empty($parts['pass']) ? '@' : '';
        $url .= !empty($parts['host']) ? $parts['host'] : '';
        $url .= !empty($parts['port']) ? ':' . $parts['port'] : '';
        $url .= !empty($parts['path']) ? $parts['path'] : '';
        $url .= !empty($parts['query']) ? '?' . $parts['query'] : '';
        $url .= !empty($parts['fragment']) ? '#' . $parts['fragment'] : '';

        return $url;
    }

    /**
     * Checks a passed in IP against a CIDR.
     * See http://stackoverflow.com/questions/594112/matching-an-ip-to-a-cidr-mask-in-php5.
     *
     * @param string $ip
     * @param string $cidr
     *
     * @return bool
     */
    public static function cidrMatch($ip, $cidr)
    {
        if (false === strpos($cidr, '/')) {
            //It doesn't have a prefix, just a straight IP match
            return $ip === $cidr;
        }

        list($subnet, $mask) = explode('/', $cidr);

        return (ip2long($ip) & ~((1 << (32 - $mask)) - 1)) === ip2long($subnet);
    }
}
