<?php

namespace Graby\HttpClient\Plugin\ServerSideRequestForgeryProtection;

final class NativeNameResolver implements NameResolver
{
    public function resolve(string $hostname): array
    {
        $ips = @gethostbynamel($hostname);

        if (false === $ips) {
            return [];
        }

        return $ips;
    }
}
