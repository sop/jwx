<?php

declare(strict_types = 1);

namespace Sop\JWX\JWK\Parameter;

use Sop\JWX\Parameter\Feature\Base64UIntValue;

/**
 * Implements 'First Prime Factor' parameter.
 *
 * @see https://tools.ietf.org/html/rfc7518#section-6.3.2.2
 */
class FirstPrimeFactorParameter extends JWKParameter
{
    use Base64UIntValue;

    /**
     * Constructor.
     *
     * @param string $p First prime factor in base64urlUInt encoding
     */
    public function __construct(string $p)
    {
        $this->_validateEncoding($p);
        parent::__construct(self::PARAM_FIRST_PRIME_FACTOR, $p);
    }
}
