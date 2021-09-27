<?php

declare(strict_types = 1);

namespace Sop\JWX\JWT\Parameter;

use Sop\JWX\JWK\JWK;
use Sop\JWX\Parameter\Parameter;

/**
 * Implements 'JSON Web Key' parameter.
 *
 * @see https://tools.ietf.org/html/rfc7515#section-4.1.3
 */
class JSONWebKeyParameter extends JWTParameter
{
    /**
     * Constructor.
     */
    public function __construct(JWK $jwk)
    {
        parent::__construct(self::PARAM_JSON_WEB_KEY, $jwk->toArray());
    }

    /**
     * {@inheritdoc}
     */
    public static function fromJSONValue($value): Parameter
    {
        if (!is_array($value)) {
            throw new \UnexpectedValueException('jwk must be an array.');
        }
        return new static(JWK::fromArray($value));
    }

    /**
     * Get value as a JWK.
     */
    public function jwk(): JWK
    {
        return JWK::fromArray($this->_value);
    }
}
