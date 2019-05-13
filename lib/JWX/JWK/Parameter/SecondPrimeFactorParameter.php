<?php

declare(strict_types = 1);

namespace Sop\JWX\JWK\Parameter;

use Sop\JWX\Parameter\Feature\Base64UIntValue;

/**
 * Implements 'Second Prime Factor' parameter.
 *
 * @see https://tools.ietf.org/html/rfc7518#section-6.3.2.3
 */
class SecondPrimeFactorParameter extends JWKParameter
{
    use Base64UIntValue;

    /**
     * Constructor.
     *
     * @param string $q Second prime factor in base64urlUInt encoding
     */
    public function __construct(string $q)
    {
        $this->_validateEncoding($q);
        parent::__construct(self::PARAM_SECOND_PRIME_FACTOR, $q);
    }
}
