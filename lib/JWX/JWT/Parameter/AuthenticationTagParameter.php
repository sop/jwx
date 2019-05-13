<?php

declare(strict_types = 1);

namespace Sop\JWX\JWT\Parameter;

use Sop\JWX\Parameter\Feature\Base64URLValue;

/**
 * Implements 'Authentication Tag' parameter.
 *
 * @see https://tools.ietf.org/html/rfc7518#section-4.7.1.2
 */
class AuthenticationTagParameter extends JWTParameter
{
    use Base64URLValue;

    /**
     * Constructor.
     *
     * @param string $tag Base64url encoded authentication tag
     */
    public function __construct(string $tag)
    {
        $this->_validateEncoding($tag);
        parent::__construct(self::PARAM_AUTHENTICATION_TAG, $tag);
    }

    /**
     * Get the authentication tag.
     *
     * @return string
     */
    public function authenticationTag(): string
    {
        return $this->string();
    }
}
