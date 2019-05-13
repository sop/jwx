<?php

declare(strict_types = 1);

namespace Sop\JWX\JWK\Parameter;

use Sop\JWX\Parameter\Feature\Base64UIntValue;

/**
 * Implements 'Modulus' parameter.
 *
 * @see https://tools.ietf.org/html/rfc7518#section-6.3.1.1
 */
class ModulusParameter extends JWKParameter
{
    use Base64UIntValue;

    /**
     * Constructor.
     *
     * @param string $n Modulus in base64urlUInt encoding
     */
    public function __construct(string $n)
    {
        $this->_validateEncoding($n);
        parent::__construct(self::PARAM_MODULUS, $n);
    }
}
