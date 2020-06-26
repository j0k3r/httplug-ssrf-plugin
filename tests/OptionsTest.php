<?php

namespace Tests\Graby\HttpClient\Plugin\ServerSideRequestForgeryProtection;

use Graby\HttpClient\Plugin\ServerSideRequestForgeryProtection\Exception\InvalidOptionException;
use Graby\HttpClient\Plugin\ServerSideRequestForgeryProtection\Options;

class OptionsTest extends \PHPUnit\Framework\TestCase
{
    /** @var Options */
    private $options;

    protected function setUp(): void
    {
        $this->options = new Options();
    }

    public function testSendCredentials(): void
    {
        $this->assertFalse($this->options->getSendCredentials());

        $this->options->enableSendCredentials();

        $this->assertTrue($this->options->getSendCredentials());

        $this->options->disableSendCredentials();

        $this->assertFalse($this->options->getSendCredentials());
    }

    public function testPinDns(): void
    {
        $this->assertFalse($this->options->getPinDns());

        $this->options->enablePinDns();

        $this->assertTrue($this->options->getPinDns());

        $this->options->disablePinDns();

        $this->assertFalse($this->options->getPinDns());
    }

    public function testInListEmptyValue(): void
    {
        $this->assertTrue($this->options->isInList('whitelist', 'ip', ''));
        $this->assertFalse($this->options->isInList('whitelist', 'port', ''));
        $this->assertTrue($this->options->isInList('whitelist', 'domain', ''));
        $this->assertFalse($this->options->isInList('whitelist', 'scheme', ''));

        $this->assertFalse($this->options->isInList('blacklist', 'ip', ''));
        $this->assertFalse($this->options->isInList('blacklist', 'port', ''));
        $this->assertFalse($this->options->isInList('blacklist', 'domain', ''));
        $this->assertFalse($this->options->isInList('blacklist', 'scheme', ''));
    }

    public function testInListDomainRegex(): void
    {
        $this->options->addToList('whitelist', 'domain', '(.*)\.fin1te\.net');

        $this->assertFalse($this->options->isInList('whitelist', 'domain', ''));
        $this->assertFalse($this->options->isInList('whitelist', 'domain', 'fin1te.net'));
        $this->assertFalse($this->options->isInList('whitelist', 'domain', 'superfin1te.net'));
        $this->assertTrue($this->options->isInList('whitelist', 'domain', 'www.fin1te.net'));
    }

    public function testInListBadList(): void
    {
        $this->expectException(InvalidOptionException::class);
        $this->expectExceptionMessage('Provided list "noo" must be "whitelist" or "blacklist"');

        $this->options->isInList('noo', 'domain', '');
    }

    public function testInListBadType(): void
    {
        $this->expectException(InvalidOptionException::class);
        $this->expectExceptionMessage('Provided type "noo" must be "ip", "port", "domain" or "scheme"');

        $this->options->isInList('whitelist', 'noo', '');
    }

    public function testGetListWithoutType(): void
    {
        $list = $this->options->getList('whitelist');

        $this->assertCount(4, $list);
        $this->assertArrayHasKey('ip', $list);
        $this->assertArrayHasKey('port', $list);
        $this->assertArrayHasKey('domain', $list);
        $this->assertArrayHasKey('scheme', $list);

        $list = $this->options->getList('blacklist');

        $this->assertCount(4, $list);
        $this->assertArrayHasKey('ip', $list);
        $this->assertArrayHasKey('port', $list);
        $this->assertArrayHasKey('domain', $list);
        $this->assertArrayHasKey('scheme', $list);
    }

    public function testGetListWhitelistWithType(): void
    {
        $this->options->addToList('whitelist', 'ip', '0.0.0.0');
        $list = $this->options->getList('whitelist', 'ip');

        $this->assertCount(1, $list);
        $this->assertArrayHasKey(0, $list);
        $this->assertSame('0.0.0.0', $list[0]);

        $list = $this->options->getList('whitelist', 'port');

        $this->assertCount(3, $list);
        $this->assertSame('80', $list[0]);
        $this->assertSame('443', $list[1]);
        $this->assertSame('8080', $list[2]);

        $this->options->addToList('whitelist', 'domain', '(.*)\.fin1te\.net');
        $list = $this->options->getList('whitelist', 'domain');

        $this->assertCount(1, $list);
        $this->assertSame('(.*)\.fin1te\.net', $list[0]);

        $list = $this->options->getList('whitelist', 'scheme');

        $this->assertCount(2, $list);
        $this->assertSame('http', $list[0]);
        $this->assertSame('https', $list[1]);
    }

    public function testGetListBlacklistWithType(): void
    {
        $list = $this->options->getList('blacklist', 'ip');

        $this->assertCount(15, $list);
        $this->assertSame('0.0.0.0/8', $list[0]);

        $this->options->addToList('blacklist', 'port', '8080');
        $list = $this->options->getList('blacklist', 'port');

        $this->assertCount(1, $list);
        $this->assertSame('8080', $list[0]);

        $this->options->addToList('blacklist', 'domain', '(.*)\.fin1te\.net');
        $list = $this->options->getList('blacklist', 'domain');

        $this->assertCount(1, $list);
        $this->assertSame('(.*)\.fin1te\.net', $list[0]);

        $this->options->addToList('blacklist', 'scheme', 'ftp');
        $list = $this->options->getList('blacklist', 'scheme');

        $this->assertCount(1, $list);
        $this->assertSame('ftp', $list[0]);
    }

    public function testGetListBadList(): void
    {
        $this->expectException(InvalidOptionException::class);
        $this->expectExceptionMessage('Provided list "noo" must be "whitelist" or "blacklist"');

        $this->options->getList('noo');
    }

    public function testGetListBadType(): void
    {
        $this->expectException(InvalidOptionException::class);
        $this->expectExceptionMessage('Provided type "noo" must be "ip", "port", "domain" or "scheme"');

        $this->options->getList('whitelist', 'noo');
    }

    public function testSetList(): void
    {
        $this->options->setList('whitelist', ['ip' => ['0.0.0.0']]);

        $this->assertSame(['0.0.0.0'], $this->options->getList('whitelist', 'ip'));

        $this->options->setList('blacklist', [22], 'port');

        $this->assertSame([22], $this->options->getList('blacklist', 'port'));
    }

    public function testSetListBadList(): void
    {
        $this->expectException(InvalidOptionException::class);
        $this->expectExceptionMessage('Provided list "noo" must be "whitelist" or "blacklist"');

        $this->options->setList('noo', []);
    }

    public function testSetListBadType(): void
    {
        $this->expectException(InvalidOptionException::class);
        $this->expectExceptionMessage('Provided type "noo" must be "ip", "port", "domain" or "scheme"');

        $this->options->setList('whitelist', [], 'noo');
    }

    public function testSetListBadTypeValue(): void
    {
        $this->expectException(InvalidOptionException::class);
        $this->expectExceptionMessage('Provided type "noo" must be "ip", "port", "domain" or "scheme"');

        $this->options->setList('whitelist', ['noo' => 'oops']);
    }

    public function testAddToListBadList(): void
    {
        $this->expectException(InvalidOptionException::class);
        $this->expectExceptionMessage('Provided list "noo" must be "whitelist" or "blacklist"');

        $this->options->addToList('noo', 'noo', 'noo');
    }

    public function testAddToListBadType(): void
    {
        $this->expectException(InvalidOptionException::class);
        $this->expectExceptionMessage('Provided type "noo" must be "ip", "port", "domain" or "scheme"');

        $this->options->addToList('whitelist', 'noo', 'noo');
    }

    public function testAddToListBadValue(): void
    {
        $this->expectException(InvalidOptionException::class);
        $this->expectExceptionMessage('Provided values cannot be empty');

        $this->options->addToList('whitelist', 'ip', null);
    }

    public function testRemoveFromListBadList(): void
    {
        $this->expectException(InvalidOptionException::class);
        $this->expectExceptionMessage('Provided list "noo" must be "whitelist" or "blacklist"');

        $this->options->removeFromList('noo', 'noo', 'noo');
    }

    public function testRemoveFromListBadType(): void
    {
        $this->expectException(InvalidOptionException::class);
        $this->expectExceptionMessage('Provided type "noo" must be "ip", "port", "domain" or "scheme"');

        $this->options->removeFromList('whitelist', 'noo', 'noo');
    }

    public function testRemoveFromListBadValue(): void
    {
        $this->expectException(InvalidOptionException::class);
        $this->expectExceptionMessage('Provided values cannot be empty');

        $this->options->removeFromList('whitelist', 'ip', null);
    }

    public function testRemoveFromList(): void
    {
        // remove not an array
        $this->options->addToList('blacklist', 'port', '8080');
        $list = $this->options->getList('blacklist', 'port');

        $this->assertCount(1, $list);
        $this->assertSame('8080', $list[0]);

        $this->options->removeFromList('blacklist', 'port', '8080');
        $list = $this->options->getList('blacklist', 'port');

        $this->assertCount(0, $list);

        // remove using an array
        $this->options->addToList('blacklist', 'scheme', 'ftp');
        $list = $this->options->getList('blacklist', 'scheme');

        $this->assertCount(1, $list);
        $this->assertSame('ftp', $list[0]);

        $this->options->removeFromList('blacklist', 'scheme', ['ftp']);
        $list = $this->options->getList('blacklist', 'scheme');

        $this->assertCount(0, $list);
    }
}
