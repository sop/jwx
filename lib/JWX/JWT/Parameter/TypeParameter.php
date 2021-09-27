<?php

declare(strict_types = 1);

namespace Sop\JWX\JWT\Parameter;

use Sop\JWX\Parameter\Feature\StringParameterValue;

/**
 * Implements 'Type' parameter.
 *
 * @see https://tools.ietf.org/html/rfc7515#section-4.1.9
 */
class TypeParameter extends JWTParameter
{
    use StringParameterValue;

    /**
     * Constructor.
     */
    public function __construct(string $type)
    {
        parent::__construct(self::PARAM_TYPE, $type);
    }
}
