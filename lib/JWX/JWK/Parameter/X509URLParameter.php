<?php

declare(strict_types = 1);

namespace Sop\JWX\JWK\Parameter;

use Sop\JWX\Parameter\Feature\StringParameterValue;

/**
 * Implements 'X.509 URL' parameter.
 *
 * @see https://tools.ietf.org/html/rfc7517#section-4.6
 */
class X509URLParameter extends JWKParameter
{
    use StringParameterValue;

    /**
     * Constructor.
     */
    public function __construct(string $uri)
    {
        parent::__construct(self::PARAM_X509_URL, $uri);
    }
}
