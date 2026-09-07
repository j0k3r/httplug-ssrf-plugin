<?php

namespace Graby\HttpClient\Plugin\ServerSideRequestForgeryProtection;

final class MockNameResolver implements NameResolver
{
    /**
     * @var array<string, string>
     */
    private array $hosts;

    /**
     * @param array<string, string> $hosts
     */
    public function __construct(array $hosts)
    {
        $this->hosts = $hosts;
    }

    public function resolve(string $hostname): array
    {
        return isset($this->hosts[$hostname]) ? [$this->hosts[$hostname]] : [];
    }
}
