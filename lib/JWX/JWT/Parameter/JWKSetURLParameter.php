<?php

declare(strict_types = 1);

namespace JWX\JWT\Parameter;

use JWX\Parameter\Feature\StringParameterValue;

/**
 * Implements 'JWK Set URL' parameter.
 *
 * @link https://tools.ietf.org/html/rfc7515#section-4.1.2
 */
class JWKSetURLParameter extends JWTParameter
{
    use StringParameterValue;
    
    /**
     * Constructor.
     *
     * @param string $uri
     */
    public function __construct(string $uri)
    {
        parent::__construct(self::PARAM_JWK_SET_URL, $uri);
    }
}
