<?php

declare(strict_types = 1);

namespace Sop\JWX\JWT\Parameter;

use Sop\JWX\Parameter\Feature\Base64URLValue;

/**
 * Implements 'Initialization Vector' parameter.
 *
 * @see https://tools.ietf.org/html/rfc7518#section-4.7.1.1
 */
class InitializationVectorParameter extends JWTParameter
{
    use Base64URLValue;

    /**
     * Constructor.
     *
     * @param string $iv Base64url encoded initialization vector
     */
    public function __construct(string $iv)
    {
        $this->_validateEncoding($iv);
        parent::__construct(self::PARAM_INITIALIZATION_VECTOR, $iv);
    }

    /**
     * Get the initialization vector.
     *
     * @return string
     */
    public function initializationVector(): string
    {
        return $this->string();
    }
}
