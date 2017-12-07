<?php

declare(strict_types = 1);

namespace JWX\JWK\Parameter;

use JWX\Parameter\Feature\StringParameterValue;

/**
 * Implements 'X.509 URL' parameter.
 *
 * @link https://tools.ietf.org/html/rfc7517#section-4.6
 */
class X509URLParameter extends JWKParameter
{
    use StringParameterValue;
    
    /**
     * Constructor.
     *
     * @param string $uri
     */
    public function __construct(string $uri)
    {
        parent::__construct(self::PARAM_X509_URL, $uri);
    }
}
