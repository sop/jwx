<?php

declare(strict_types = 1);

namespace Sop\JWX\JWK\Parameter;

use Sop\JWX\Parameter\Feature\Base64UIntValue;

/**
 * Implements 'First Factor CRT Exponent' parameter.
 *
 * @see https://tools.ietf.org/html/rfc7518#section-6.3.2.4
 */
class FirstFactorCRTExponentParameter extends JWKParameter
{
    use Base64UIntValue;

    /**
     * Constructor.
     *
     * @param string $dp First factor CRT exponent in base64urlUInt encoding
     */
    public function __construct(string $dp)
    {
        $this->_validateEncoding($dp);
        parent::__construct(self::PARAM_FIRST_FACTOR_CRT_EXPONENT, $dp);
    }
}
