<?php

declare(strict_types = 1);

namespace Sop\JWX\JWK\Parameter;

use Sop\JWX\Parameter\Feature\Base64UIntValue;

/**
 * Implements 'Private Exponent' parameter.
 *
 * @see https://tools.ietf.org/html/rfc7518#section-6.3.2.1
 */
class PrivateExponentParameter extends JWKParameter
{
    use Base64UIntValue;

    /**
     * Constructor.
     *
     * @param string $d Private exponent in base64urlUInt encoding
     */
    public function __construct(string $d)
    {
        $this->_validateEncoding($d);
        parent::__construct(self::PARAM_PRIVATE_EXPONENT, $d);
    }
}
