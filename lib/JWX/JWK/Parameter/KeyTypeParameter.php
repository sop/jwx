<?php

declare(strict_types = 1);

namespace JWX\JWK\Parameter;

use JWX\Parameter\Feature\StringParameterValue;

/**
 * Implements 'Key Type' parameter.
 *
 * @link https://tools.ietf.org/html/rfc7517#section-4.1
 */
class KeyTypeParameter extends JWKParameter
{
    use StringParameterValue;
    
    /**
     * Octet sequence key type.
     */
    const TYPE_OCT = "oct";
    
    /**
     * RSA key type.
     */
    const TYPE_RSA = "RSA";
    
    /**
     * Elliptic curve key type.
     */
    const TYPE_EC = "EC";
    
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
