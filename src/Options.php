<?php

namespace Graby\HttpClient\Plugin\ServerSideRequestForgeryProtection;

use Graby\HttpClient\Plugin\ServerSideRequestForgeryProtection\Exception\InvalidOptionException;

class Options
{
    /** @var array */
    private static $availableType = [
        'ip',
        'port',
        'domain',
        'scheme',
    ];
    /**
     * Allow credentials in a URL.
     *
     * @var bool
     */
    private $sendCredentials = false;

    /**
     * Pin DNS records.
     *
     * @var bool
     */
    private $pinDns = false;

    /**
     * blacklist and whitelist.
     *
     * @var array
     */
    private $lists = [
        'whitelist' => [
            'ip' => [],
            'port' => ['80', '443', '8080'],
            'domain' => [],
            'scheme' => ['http', 'https'],
        ],
        'blacklist' => [
            'ip' => [
                '0.0.0.0/8',
                '10.0.0.0/8',
                '100.64.0.0/10',
                '127.0.0.0/8',
                '169.254.0.0/16',
                '172.16.0.0/12',
                '192.0.0.0/29',
                '192.0.2.0/24',
                '192.88.99.0/24',
                '192.168.0.0/16',
                '198.18.0.0/15',
                '198.51.100.0/24',
                '203.0.113.0/24',
                '224.0.0.0/4',
                '240.0.0.0/4',
            ],
            'port' => [],
            'domain' => [],
            'scheme' => [],
        ],
    ];

    /**
     * Get send credentials option.
     */
    public function getSendCredentials(): bool
    {
        return $this->sendCredentials;
    }

    /**
     * Enable sending of credenitals
     * This is potentially a security risk.
     */
    public function enableSendCredentials(): self
    {
        $this->sendCredentials = true;

        return $this;
    }

    /**
     * Disable sending of credentials.
     */
    public function disableSendCredentials(): self
    {
        $this->sendCredentials = false;

        return $this;
    }

    /**
     * Get pin DNS option.
     */
    public function getPinDns(): bool
    {
        return $this->pinDns;
    }

    /**
     * Enable DNS pinning.
     */
    public function enablePinDns(): self
    {
        $this->pinDns = true;

        return $this;
    }

    /**
     * Disable DNS pinning.
     */
    public function disablePinDns(): self
    {
        $this->pinDns = false;

        return $this;
    }

    /**
     * Checks if a specific value is in a list.
     *
     * @param string $listName Accepts 'whitelist' or 'blacklist
     *
     * @throws InvalidOptionException
     */
    public function isInList(string $listName, string $type, string $value): bool
    {
        $this->checkListByName($listName);
        $value = (string) $value;

        if (!\array_key_exists($type, $this->lists[$listName])) {
            throw InvalidOptionException::invalidType($type, self::$availableType);
        }

        if (empty($this->lists[$listName][$type])) {
            return 'whitelist' === $listName;
        }

        //For domains, a regex match is needed
        if ('domain' === $type) {
            foreach ($this->lists[$listName][$type] as $domain) {
                if (preg_match('/^' . $domain . '$/i', $value)) {
                    return true;
                }
            }

            return false;
        }

        return \in_array($value, $this->lists[$listName][$type], true);
    }

    /**
     * Returns a specific list.
     *
     * @param string $listName Accepts 'whitelist' or 'blacklist
     *
     * @throws InvalidOptionException
     */
    public function getList(string $listName, string $type = null): array
    {
        $this->checkListByName($listName);

        if (null !== $type) {
            if (!\array_key_exists($type, $this->lists[$listName])) {
                throw InvalidOptionException::invalidType($type, self::$availableType);
            }

            return $this->lists[$listName][$type];
        }

        return $this->lists[$listName];
    }

    /**
     * Sets a list, the values must be passed as an array.
     *
     * @param string $listName Accepts 'whitelist' or 'blacklist
     *
     * @throws InvalidOptionException
     */
    public function setList(string $listName, array $values, string $type = null): self
    {
        $this->checkListByName($listName);

        if (null !== $type) {
            if (!\array_key_exists($type, $this->lists[$listName])) {
                throw InvalidOptionException::invalidType($type, self::$availableType);
            }

            $this->lists[$listName][$type] = $values;

            return $this;
        }

        foreach ($values as $type => $value) {
            if (!\in_array($type, self::$availableType, true)) {
                throw InvalidOptionException::invalidType($type, self::$availableType);
            }

            $this->lists[$listName][$type] = $value;
        }

        return $this;
    }

    /**
     * Adds a value/values to a specific list.
     *
     * @param string       $listName Accepts 'whitelist' or 'blacklist
     * @param array|string $values
     *
     * @throws InvalidOptionException
     */
    public function addToList(string $listName, string $type, $values = null): self
    {
        $this->checkListByName($listName);

        if (!\array_key_exists($type, $this->lists[$listName])) {
            throw InvalidOptionException::invalidType($type, self::$availableType);
        }

        if (empty($values)) {
            throw InvalidOptionException::emptyValues();
        }

        //Cast single values to an array
        $values = (array) $values;

        foreach ($values as $value) {
            if (!\in_array($value, $this->lists[$listName][$type], true)) {
                $this->lists[$listName][$type][] = $value;
            }
        }

        return $this;
    }

    /**
     * Removes a value/values from a specific list.
     *
     * @param string       $listName Accepts 'whitelist' or 'blacklist
     * @param array|string $values
     *
     * @throws InvalidOptionException
     */
    public function removeFromList(string $listName, string $type, $values = null): self
    {
        $this->checkListByName($listName);

        if (!\array_key_exists($type, $this->lists[$listName])) {
            throw InvalidOptionException::invalidType($type, self::$availableType);
        }

        if (empty($values)) {
            throw InvalidOptionException::emptyValues();
        }

        //Cast single values to an array
        $values = (array) $values;

        $this->lists[$listName][$type] = array_diff($this->lists[$listName][$type], $values);

        return $this;
    }

    /**
     * @param string $listName Accepts 'whitelist' or 'blacklist
     *
     * @throws InvalidOptionException
     */
    private function checkListByName($listName): void
    {
        if (!isset($this->lists[$listName])) {
            throw InvalidOptionException::invalidListName($listName);
        }
    }
}
