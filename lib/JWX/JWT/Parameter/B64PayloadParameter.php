<?php

declare(strict_types = 1);

namespace JWX\JWT\Parameter;

/**
 * Implements 'base64url-encode payload' parameter.
 *
 * @link https://tools.ietf.org/html/rfc7797#section-3
 */
class B64PayloadParameter extends JWTParameter
{
    /**
     * Constructor.
     *
     * @param bool $flag
     */
    public function __construct(bool $flag)
    {
        parent::__construct(self::PARAM_BASE64URL_ENCODE_PAYLOAD, $flag);
    }
    
    /**
     * Initialize from a JSON value.
     *
     * @param bool $value
     * @return self
     */
    public static function fromJSONValue($value): self
    {
        return new self(boolval($value));
    }
}
