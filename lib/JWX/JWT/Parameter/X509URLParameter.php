<?php

declare(strict_types = 1);

namespace Sop\JWX\JWT\Parameter;

use Sop\JWX\Parameter\Feature\StringParameterValue;

/**
 * Implements 'X.509 URL' parameter.
 *
 * @see https://tools.ietf.org/html/rfc7515#section-4.1.5
 */
class X509URLParameter extends JWTParameter
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
