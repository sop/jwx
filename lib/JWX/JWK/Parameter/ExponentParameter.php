<?php

declare(strict_types = 1);

namespace Sop\JWX\JWK\Parameter;

use Sop\JWX\Parameter\Feature\Base64UIntValue;

/**
 * Implements 'Exponent' parameter.
 *
 * @see https://tools.ietf.org/html/rfc7518#section-6.3.1.2
 */
class ExponentParameter extends JWKParameter
{
    use Base64UIntValue;

    /**
     * Constructor.
     *
     * @param string $e Exponent in base64urlUInt encoding
     */
    public function __construct(string $e)
    {
        $this->_validateEncoding($e);
        parent::__construct(self::PARAM_EXPONENT, $e);
    }
}
