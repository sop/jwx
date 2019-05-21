<?php

declare(strict_types = 1);

namespace Sop\JWX\JWT\Claim;

use Sop\JWX\JWT\Claim\Validator\Validator;
use Sop\JWX\JWT\ValidationContext;

/**
 * Represents a JWT claim.
 *
 * @see https://tools.ietf.org/html/rfc7519#section-4
 */
class Claim
{
    /**
     * Claim name.
     *
     * @var string
     */
    protected $_name;

    /**
     * Claim value.
     *
     * @var mixed
     */
    protected $_value;

    /**
     * Claim validator.
     *
     * @var null|Validator
     */
    protected $_validator;

    /**
     * Constructor.
     *
     * @param string         $name      Claim name
     * @param mixed          $value     Claim value
     * @param null|Validator $validator Claim validator or null if claim doesn't
     *                                  provide validation
     */
    public function __construct(string $name, $value, ?Validator $validator = null)
    {
        $this->_name = $name;
        $this->_value = $value;
        $this->_validator = $validator;
    }

    /**
     * Initialize from a name and a value.
     *
     * Returns a specific claim object if applicable.
     *
     * @param string $name  Claim name
     * @param mixed  $value Claim value
     *
     * @return Claim
     */
    public static function fromNameAndValue(string $name, $value): Claim
    {
        if (array_key_exists($name, RegisteredClaim::MAP_NAME_TO_CLASS)) {
            $cls = RegisteredClaim::MAP_NAME_TO_CLASS[$name];
            return $cls::fromJSONValue($value);
        }
        return new self($name, $value);
    }

    /**
     * Get the claim name.
     *
     * @return string
     */
    public function name(): string
    {
        return $this->_name;
    }

    /**
     * Get the claim value.
     *
     * @return mixed
     */
    public function value()
    {
        return $this->_value;
    }

    /**
     * Validate the claim against a given constraint.
     *
     * @param mixed $constraint Constraint value
     *
     * @return bool True if the claim is valid
     */
    public function validate($constraint): bool
    {
        // if claim has no validator, consider validation failed
        if (!isset($this->_validator)) {
            return false;
        }
        return $this->_validator->validate($this->_value, $constraint);
    }

    /**
     * Validate the claim in a given context.
     *
     * Overridden in specific claims that provide default validation.
     *
     * @param ValidationContext $ctx
     *
     * @return bool True if claim is valid
     */
    public function validateWithContext(ValidationContext $ctx): bool
    {
        // if validator has no constraint for the claim
        if (!$ctx->hasConstraint($this->_name)) {
            return true;
        }
        // if validation context has an explicitly defined validator for the claim
        if ($ctx->hasValidator($this->_name)) {
            return $ctx->validator($this->_name)
                ->validate($this->_value, $ctx->constraint($this->_name));
        }
        // validate using claim's default validator
        return $this->validate($ctx->constraint($this->_name));
    }
}
