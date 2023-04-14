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
        $this->assertTrue($this->options->isInList(Options::LIST_WHITELIST, 'ip', ''));
        $this->assertFalse($this->options->isInList(Options::LIST_WHITELIST, 'port', ''));
        $this->assertTrue($this->options->isInList(Options::LIST_WHITELIST, 'domain', ''));
        $this->assertFalse($this->options->isInList(Options::LIST_WHITELIST, 'scheme', ''));

        $this->assertFalse($this->options->isInList(Options::LIST_BLACKLIST, 'ip', ''));
        $this->assertFalse($this->options->isInList(Options::LIST_BLACKLIST, 'port', ''));
        $this->assertFalse($this->options->isInList(Options::LIST_BLACKLIST, 'domain', ''));
        $this->assertFalse($this->options->isInList(Options::LIST_BLACKLIST, 'scheme', ''));
    }

    public function testInListDomainRegex(): void
    {
        $this->options->addToList(Options::LIST_WHITELIST, 'domain', '(.*)\.fin1te\.net');

        $this->assertFalse($this->options->isInList(Options::LIST_WHITELIST, 'domain', ''));
        $this->assertFalse($this->options->isInList(Options::LIST_WHITELIST, 'domain', 'fin1te.net'));
        $this->assertFalse($this->options->isInList(Options::LIST_WHITELIST, 'domain', 'superfin1te.net'));
        $this->assertTrue($this->options->isInList(Options::LIST_WHITELIST, 'domain', 'www.fin1te.net'));
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

        $this->options->isInList(Options::LIST_WHITELIST, 'noo', '');
    }

    public function testGetListWithoutType(): void
    {
        $list = $this->options->getList(Options::LIST_WHITELIST);

        $this->assertCount(4, $list);
        $this->assertArrayHasKey('ip', $list);
        $this->assertArrayHasKey('port', $list);
        $this->assertArrayHasKey('domain', $list);
        $this->assertArrayHasKey('scheme', $list);

        $list = $this->options->getList(Options::LIST_BLACKLIST);

        $this->assertCount(4, $list);
        $this->assertArrayHasKey('ip', $list);
        $this->assertArrayHasKey('port', $list);
        $this->assertArrayHasKey('domain', $list);
        $this->assertArrayHasKey('scheme', $list);
    }

    public function testGetListWhitelistWithType(): void
    {
        $this->options->addToList(Options::LIST_WHITELIST, 'ip', '0.0.0.0');
        $list = $this->options->getList(Options::LIST_WHITELIST, 'ip');

        $this->assertCount(1, $list);
        $this->assertArrayHasKey(0, $list);
        $this->assertSame('0.0.0.0', $list[0]);

        $list = $this->options->getList(Options::LIST_WHITELIST, 'port');

        $this->assertCount(3, $list);
        $this->assertSame('80', $list[0]);
        $this->assertSame('443', $list[1]);
        $this->assertSame('8080', $list[2]);

        $this->options->addToList(Options::LIST_WHITELIST, 'domain', '(.*)\.fin1te\.net');
        $list = $this->options->getList(Options::LIST_WHITELIST, 'domain');

        $this->assertCount(1, $list);
        $this->assertSame('(.*)\.fin1te\.net', $list[0]);

        $list = $this->options->getList(Options::LIST_WHITELIST, 'scheme');

        $this->assertCount(2, $list);
        $this->assertSame('http', $list[0]);
        $this->assertSame('https', $list[1]);
    }

    public function testGetListBlacklistWithType(): void
    {
        $list = $this->options->getList(Options::LIST_BLACKLIST, 'ip');

        $this->assertCount(15, $list);
        $this->assertSame('0.0.0.0/8', $list[0]);

        $this->options->addToList(Options::LIST_BLACKLIST, 'port', 8080);
        $list = $this->options->getList(Options::LIST_BLACKLIST, 'port');

        $this->assertCount(1, $list);
        $this->assertSame('8080', $list[0]);

        $this->options->addToList(Options::LIST_BLACKLIST, 'domain', '(.*)\.fin1te\.net');
        $list = $this->options->getList(Options::LIST_BLACKLIST, 'domain');

        $this->assertCount(1, $list);
        $this->assertSame('(.*)\.fin1te\.net', $list[0]);

        $this->options->addToList(Options::LIST_BLACKLIST, 'scheme', 'ftp');
        $list = $this->options->getList(Options::LIST_BLACKLIST, 'scheme');

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

        $this->options->getList(Options::LIST_WHITELIST, 'noo');
    }

    public function testSetList(): void
    {
        $this->options->setList(Options::LIST_WHITELIST, ['ip' => ['0.0.0.0']]);

        $this->assertSame(['0.0.0.0'], $this->options->getList(Options::LIST_WHITELIST, 'ip'));

        $this->options->setList(Options::LIST_BLACKLIST, [22], 'port');

        $this->assertSame(['22'], $this->options->getList(Options::LIST_BLACKLIST, 'port'));
    }

    public function testSetListPreservesNonOverlapping(): void
    {
        $this->options->setList(Options::LIST_BLACKLIST, ['port' => [1234]]);
        $this->assertSame(['1234'], $this->options->getList(Options::LIST_BLACKLIST, 'port'));

        $this->options->setList(Options::LIST_BLACKLIST, ['ip' => ['0.0.0.0']]);
        $this->assertSame(['0.0.0.0'], $this->options->getList(Options::LIST_BLACKLIST, 'ip'));

        $this->assertSame(['1234'], $this->options->getList(Options::LIST_BLACKLIST, 'port'), 'Setting partial list should not override keys that were omitted.');
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

        $this->options->setList(Options::LIST_WHITELIST, [], 'noo');
    }

    public function testSetListBadTypeValue(): void
    {
        $this->expectException(InvalidOptionException::class);
        $this->expectExceptionMessage('Provided type "noo" must be "ip", "port", "domain" or "scheme"');

        $this->options->setList(Options::LIST_WHITELIST, ['noo' => 'oops']);
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

        $this->options->addToList(Options::LIST_WHITELIST, 'noo', 'noo');
    }

    public function testAddToListBadValue(): void
    {
        $this->expectException(InvalidOptionException::class);
        $this->expectExceptionMessage('Provided values cannot be empty');

        $this->options->addToList(Options::LIST_WHITELIST, 'ip', []);
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

        $this->options->removeFromList(Options::LIST_WHITELIST, 'noo', 'noo');
    }

    public function testRemoveFromListBadValue(): void
    {
        $this->expectException(InvalidOptionException::class);
        $this->expectExceptionMessage('Provided values cannot be empty');

        $this->options->removeFromList(Options::LIST_WHITELIST, 'ip', []);
    }

    public function testRemoveFromList(): void
    {
        // remove not an array
        $this->options->addToList(Options::LIST_BLACKLIST, 'port', 8080);
        $list = $this->options->getList(Options::LIST_BLACKLIST, 'port');

        $this->assertCount(1, $list);
        $this->assertSame('8080', $list[0]);

        $this->options->removeFromList(Options::LIST_BLACKLIST, 'port', 8080);
        $list = $this->options->getList(Options::LIST_BLACKLIST, 'port');

        $this->assertCount(0, $list);

        // remove using an array
        $this->options->addToList(Options::LIST_BLACKLIST, 'scheme', 'ftp');
        $list = $this->options->getList(Options::LIST_BLACKLIST, 'scheme');

        $this->assertCount(1, $list);
        $this->assertSame('ftp', $list[0]);

        $this->options->removeFromList(Options::LIST_BLACKLIST, 'scheme', ['ftp']);
        $list = $this->options->getList(Options::LIST_BLACKLIST, 'scheme');

        $this->assertCount(0, $list);
    }

    public function testNumericPortIsInList(): void
    {
        $this->options->addToList(Options::LIST_BLACKLIST, 'port', 8080);
        $this->assertTrue($this->options->isInList(Options::LIST_BLACKLIST, 'port', '8080'));
    }

    public function testInvalidTypeCoverage(): void
    {
        // This would be disallowed by static analysis but code coverage complains.
        $this->expectException(\TypeError::class);
        $this->expectExceptionMessage('Option values can only be strings or ints.');

        $this->options->addToList(Options::LIST_BLACKLIST, 'port', (object) ['dummy' => true]);
    }
}
