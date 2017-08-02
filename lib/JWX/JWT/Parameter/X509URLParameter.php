<?php

namespace JWX\JWT\Parameter;

use JWX\Parameter\Feature\StringParameterValue;

/**
 * Implements 'X.509 URL' parameter.
 *
 * @link https://tools.ietf.org/html/rfc7515#section-4.1.5
 */
class X509URLParameter extends JWTParameter
{
    use StringParameterValue;
    
    /**
     * Constructor.
     *
     * @param string $uri
     */
    public function __construct($uri)
    {
        parent::__construct(self::PARAM_X509_URL, (string) $uri);
    }
}
