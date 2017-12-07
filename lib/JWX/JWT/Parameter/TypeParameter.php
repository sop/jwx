<?php

declare(strict_types = 1);

namespace JWX\JWT\Parameter;

use JWX\Parameter\Feature\StringParameterValue;

/**
 * Implements 'Type' parameter.
 *
 * @link https://tools.ietf.org/html/rfc7515#section-4.1.9
 */
class TypeParameter extends JWTParameter
{
    use StringParameterValue;
    
    /**
     * Constructor.
     *
     * @param string $type
     */
    public function __construct(string $type)
    {
        parent::__construct(self::PARAM_TYPE, $type);
    }
}
