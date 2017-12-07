<?php

declare(strict_types = 1);

namespace JWX\JWK\Parameter;

use JWX\Parameter\Feature\StringParameterValue;

/**
 * Implements 'Algorithm' parameter.
 *
 * @link https://tools.ietf.org/html/rfc7517#section-4.4
 */
class AlgorithmParameter extends JWKParameter
{
    use StringParameterValue;
    
    /**
     * Constructor.
     *
     * @param string $algo Algorithm name
     */
    public function __construct(string $algo)
    {
        parent::__construct(self::PARAM_ALGORITHM, $algo);
    }
}
