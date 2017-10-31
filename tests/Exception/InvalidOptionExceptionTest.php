<?php

namespace Graby\HttpClient\Plugin\ServerSideRequestForgeryProtection\Exception;

class InvalidOptionExceptionTest extends \PHPUnit_Framework_TestCase
{
    public function testInvalidType()
    {
        $exception = InvalidOptionException::invalidType('ippp', ['ip', 'port', 'domain', 'scheme']);

        $this->assertSame('Provided type "ippp" must be "ip", "port", "domain" or "scheme"', $exception->getMessage());
    }
}
