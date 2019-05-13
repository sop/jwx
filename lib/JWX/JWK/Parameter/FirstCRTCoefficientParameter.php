<?php

declare(strict_types = 1);

namespace Sop\JWX\JWK\Parameter;

use Sop\JWX\Parameter\Feature\Base64UIntValue;

/**
 * Implements 'First CRT Coefficient' parameter.
 *
 * @see https://tools.ietf.org/html/rfc7518#section-6.3.2.6
 */
class FirstCRTCoefficientParameter extends JWKParameter
{
    use Base64UIntValue;

    /**
     * Constructor.
     *
     * @param string $qi First CRT coefficient in base64urlUInt encoding
     */
    public function __construct(string $qi)
    {
        $this->_validateEncoding($qi);
        parent::__construct(self::PARAM_FIRST_CRT_COEFFICIENT, $qi);
    }
}
