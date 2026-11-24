<?php

namespace Tests\Graby\HttpClient\Plugin\ServerSideRequestForgeryProtection;

use Graby\HttpClient\Plugin\ServerSideRequestForgeryProtection\NameResolver;

final class MockNameResolver implements NameResolver
{
    /**
     * @var array<string, string|list<string>>
     */
    private array $hosts;

    /**
     * @param array<string, string|list<string>> $hosts
     */
    public function __construct(array $hosts)
    {
        $this->hosts = $hosts;
    }

    public function resolve(string $hostname): array
    {
        return (array) ($this->hosts[$hostname] ?? []);
    }
}
