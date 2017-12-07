<?php

declare(strict_types = 1);

namespace JWX\JWT\Parameter;

use JWX\Parameter\Feature\Base64URLValue;

/**
 * Implements 'Authentication Tag' parameter.
 *
 * @link https://tools.ietf.org/html/rfc7518#section-4.7.1.2
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
