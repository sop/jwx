<?php

declare(strict_types = 1);

namespace Sop\JWX\JWK\Parameter;

use Sop\JWX\Parameter\Feature\Base64UIntValue;

/**
 * Implements 'Second Factor CRT Exponent' parameter.
 *
 * @see https://tools.ietf.org/html/rfc7518#section-6.3.2.5
 */
class SecondFactorCRTExponentParameter extends JWKParameter
{
    use Base64UIntValue;

    /**
     * Constructor.
     *
     * @param string $dq Second factor CRT exponent in base64urlUInt encoding
     */
    public function __construct(string $dq)
    {
        $this->_validateEncoding($dq);
        parent::__construct(self::PARAM_SECOND_FACTOR_CRT_EXPONENT, $dq);
    }
}
