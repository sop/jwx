<?php

namespace JWX\JWK\Parameter;

use JWX\Parameter\Feature\Base64UIntValue;

/**
 * Implements 'First CRT Coefficient' parameter.
 *
 * @link https://tools.ietf.org/html/rfc7518#section-6.3.2.6
 */
class FirstCRTCoefficientParameter extends JWKParameter
{
    use Base64UIntValue;
    
    /**
     * Constructor.
     *
     * @param string $qi First CRT coefficient in base64urlUInt encoding
     */
    public function __construct($qi)
    {
        $this->_validateEncoding($qi);
        parent::__construct(self::PARAM_FIRST_CRT_COEFFICIENT, $qi);
    }
}
