<?php

declare(strict_types = 1);

namespace Sop\JWX\JWK\Parameter;

use Sop\JWX\Parameter\Feature\Base64URLValue;

/**
 * Implements 'Key Value' parameter.
 *
 * @see https://tools.ietf.org/html/rfc7518#section-6.4.1
 */
class KeyValueParameter extends JWKParameter
{
    use Base64URLValue;

    /**
     * Constructor.
     *
     * @param string $key Base64url encoded key
     */
    public function __construct(string $key)
    {
        $this->_validateEncoding($key);
        parent::__construct(self::PARAM_KEY_VALUE, $key);
    }

    /**
     * Get key in binary format.
     */
    public function key(): string
    {
        return $this->string();
    }
}
