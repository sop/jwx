<?php

declare(strict_types = 1);

namespace Sop\JWX\JWK\Parameter;

use Sop\JWX\Parameter\Feature\ArrayParameterValue;

/**
 * Implements 'Other Primes Info' parameter.
 *
 * @todo Implement the underlying data structure
 *
 * @see https://tools.ietf.org/html/rfc7518#section-6.3.2.7
 */
class OtherPrimesInfoParameter extends JWKParameter
{
    use ArrayParameterValue;

    /**
     * Constructor.
     *
     * @param array[] ...$primes
     */
    public function __construct(...$primes)
    {
        parent::__construct(self::PARAM_OTHER_PRIMES_INFO, $primes);
    }
}
