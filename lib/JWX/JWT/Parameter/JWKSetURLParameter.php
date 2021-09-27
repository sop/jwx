<?php

declare(strict_types = 1);

namespace Sop\JWX\JWT\Parameter;

use Sop\JWX\Parameter\Feature\StringParameterValue;

/**
 * Implements 'JWK Set URL' parameter.
 *
 * @see https://tools.ietf.org/html/rfc7515#section-4.1.2
 */
class JWKSetURLParameter extends JWTParameter
{
    use StringParameterValue;

    /**
     * Constructor.
     */
    public function __construct(string $uri)
    {
        parent::__construct(self::PARAM_JWK_SET_URL, $uri);
    }
}
