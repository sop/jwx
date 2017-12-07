<?php

declare(strict_types = 1);

namespace JWX\JWT\Parameter;

use JWX\JWK\JWK;

/**
 * Implements 'JSON Web Key' parameter.
 *
 * @link https://tools.ietf.org/html/rfc7515#section-4.1.3
 */
class JSONWebKeyParameter extends JWTParameter
{
    /**
     * Constructor.
     *
     * @param JWK $jwk
     */
    public function __construct(JWK $jwk)
    {
        parent::__construct(self::PARAM_JSON_WEB_KEY, $jwk->toArray());
    }
    
    /**
     *
     * {@inheritdoc}
     */
    public static function fromJSONValue($value): self
    {
        if (!is_array($value)) {
            throw new \UnexpectedValueException("jwk must be an array.");
        }
        return new static(JWK::fromArray($value));
    }
    
    /**
     * Get value as a JWK.
     *
     * @return JWK
     */
    public function jwk(): JWK
    {
        return JWK::fromArray($this->_value);
    }
}
