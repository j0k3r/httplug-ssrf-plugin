<?php

namespace Graby\HttpClient\Plugin\ServerSideRequestForgeryProtection;

final class NativeNameResolver implements NameResolver
{
    public function resolve(string $hostname): array
    {
        $records = @socket_addrinfo_lookup(trim($hostname, '[]'), null, [
            'ai_socktype' => \SOCK_STREAM,
        ]);

        if (false === $records) {
            return [];
        }

        $ips = [];
        foreach ($records as $record) {
            $address = socket_addrinfo_explain($record)['ai_addr'] ?? null;
            if (!\is_array($address)) {
                return [];
            }

            $ip = $address['sin_addr'] ?? $address['sin6_addr'] ?? null;
            if (!\is_string($ip)) {
                return [];
            }

            $ips[] = $ip;
        }

        return array_values(array_unique($ips));
    }
}
