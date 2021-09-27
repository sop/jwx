<?php

declare(strict_types = 1);

namespace Sop\JWX\JWK\Parameter;

use Sop\JWX\Parameter\Feature\StringParameterValue;

/**
 * Implements 'Key Type' parameter.
 *
 * @see https://tools.ietf.org/html/rfc7517#section-4.1
 */
class KeyTypeParameter extends JWKParameter
{
    use StringParameterValue;

    /**
     * Octet sequence key type.
     */
    public const TYPE_OCT = 'oct';

    /**
     * RSA key type.
     */
    public const TYPE_RSA = 'RSA';

    /**
     * Elliptic curve key type.
     */
    public const TYPE_EC = 'EC';

    /**
     * Constructor.
     *
     * @param string $type Key type
     */
    public function __construct(string $type)
    {
        parent::__construct(self::PARAM_KEY_TYPE, $type);
    }
}
