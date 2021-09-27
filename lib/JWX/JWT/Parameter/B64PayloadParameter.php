<?php

declare(strict_types = 1);

namespace Sop\JWX\JWT\Parameter;

use Sop\JWX\Parameter\Parameter;

/**
 * Implements 'base64url-encode payload' parameter.
 *
 * @see https://tools.ietf.org/html/rfc7797#section-3
 */
class B64PayloadParameter extends JWTParameter
{
    /**
     * Constructor.
     */
    public function __construct(bool $flag)
    {
        parent::__construct(self::PARAM_BASE64URL_ENCODE_PAYLOAD, $flag);
    }

    /**
     * Initialize from a JSON value.
     *
     * @param bool $value
     *
     * @return self
     */
    public static function fromJSONValue($value): Parameter
    {
        return new self(boolval($value));
    }
}
