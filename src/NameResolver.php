<?php

namespace Graby\HttpClient\Plugin\ServerSideRequestForgeryProtection;

interface NameResolver
{
    /**
     * @return list<string>
     */
    public function resolve(string $host): array;
}
