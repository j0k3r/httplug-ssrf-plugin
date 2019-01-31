<?php

namespace Tests\Graby\HttpClient\Plugin\ServerSideRequestForgeryProtection\Exception;

use Graby\HttpClient\Plugin\ServerSideRequestForgeryProtection\Exception\InvalidOptionException;

class InvalidOptionExceptionTest extends \PHPUnit\Framework\TestCase
{
    public function testInvalidType()
    {
        $exception = InvalidOptionException::invalidType('ippp', ['ip', 'port', 'domain', 'scheme']);

        $this->assertSame('Provided type "ippp" must be "ip", "port", "domain" or "scheme"', $exception->getMessage());
    }
}
