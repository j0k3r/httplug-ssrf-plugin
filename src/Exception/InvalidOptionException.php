<?php

namespace Graby\HttpClient\Plugin\ServerSideRequestForgeryProtection\Exception;

final class InvalidOptionException extends \Exception implements SsrfException
{
    /**
     * @param string $type
     *
     * @return static
     */
    public static function invalidType($type, array $expectedTypes): self
    {
        $expectedTypesList = '"' . implode('", "', \array_slice($expectedTypes, 0, -1))
            . '" or "' . $expectedTypes[\count($expectedTypes) - 1] . '"';

        return new static(sprintf('Provided type "%s" must be %s', $type, $expectedTypesList));
    }

    /**
     * @param string $listName
     *
     * @return static
     */
    public static function invalidListName($listName): self
    {
        return new static(sprintf('Provided list "%s" must be "whitelist" or "blacklist"', $listName));
    }

    public static function emptyValues(): self
    {
        return new static('Provided values cannot be empty');
    }
}
