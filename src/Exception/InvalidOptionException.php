<?php

namespace Graby\HttpClient\Plugin\ServerSideRequestForgeryProtection\Exception;

class InvalidOptionException extends \Exception implements SsrfException
{
    /**
     * @param string $type
     * @param array  $expectedTypes
     *
     * @return static
     */
    public static function invalidType($type, array $expectedTypes)
    {
        $expectedTypesList = '"' . implode('", "', array_slice($expectedTypes, 0, -1))
            . '" or "' . $expectedTypes[count($expectedTypes) - 1] . '"';

        return new static(sprintf('Provided type "%s" must be %s', $type, $expectedTypesList));
    }

    /**
     * @param string $listName
     *
     * @return static
     */
    public static function invalidListName($listName)
    {
        return new static(sprintf('Provided list "%s" must be "whitelist" or "blacklist"', $listName));
    }

    public static function emptyValues()
    {
        return new static('Provided values cannot be empty');
    }

    public static function invalidValues($values)
    {
        return new static(sprintf('Provided values must be an array, "%s" given', gettype($values)));
    }
}
