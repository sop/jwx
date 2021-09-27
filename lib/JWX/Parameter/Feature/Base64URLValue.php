<?php

declare(strict_types = 1);

namespace Sop\JWX\Parameter\Feature;

use Sop\JWX\Parameter\Parameter;
use Sop\JWX\Util\Base64;

/**
 * Trait for parameters having Base64url value.
 */
trait Base64URLValue
{
    use StringParameterValue;

    /**
     * Get the parameter value.
     *
     * @return string
     */
    abstract public function value();

    /**
     * Initialize from native value.
     *
     * Value shall be encoded using Base64url encoding.
     *
     * @return self
     */
    public static function fromString(string $value): Parameter
    {
        return new static(Base64::urlEncode($value));
    }

    /**
     * Get the parameter value as a decoded string.
     */
    public function string(): string
    {
        return Base64::urlDecode($this->value());
    }

    /**
     * Validate that value is validly base64url encoded.
     *
     * @throws \UnexpectedValueException
     *
     * @return self
     */
    protected function _validateEncoding(string $value)
    {
        if (!Base64::isValidURLEncoding($value)) {
            throw new \UnexpectedValueException(
                'Value must be base64url encoded.');
        }
        return $this;
    }
}
