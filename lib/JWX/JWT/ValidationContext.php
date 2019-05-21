<?php

declare(strict_types = 1);

namespace Sop\JWX\JWT;

use Sop\JWX\JWK\JWK;
use Sop\JWX\JWK\JWKSet;
use Sop\JWX\JWT\Claim\RegisteredClaim;
use Sop\JWX\JWT\Claim\Validator\Validator;
use Sop\JWX\JWT\Exception\ValidationException;

/**
 * Class to provide context for claims validation.
 *
 * Validation constraints are variables, that are compared against the claims.
 * Validation of the expiration, not-before and not-after claims is provided by
 * default.
 *
 * Constraints configured for the validation context must be present in the
 * validated set of claims, or else validation fails.
 *
 * Context also provides a set of JSON Web Keys, that shall be used for the
 * JWS signature validation or JWE payload decryption.
 *
 * Registered claims provide their own validation logic. Claims that are not
 * supported by this library must be provided with an explicit validator along
 * with the constraint.
 */
class ValidationContext
{
    /**
     * Reference time.
     *
     * @var int
     */
    protected $_refTime;

    /**
     * Leeway in seconds for the reference time constraints.
     *
     * @var int
     */
    protected $_leeway;

    /**
     * Validation constraints.
     *
     * @var array
     */
    protected $_constraints;

    /**
     * Explicitly defined validators for named claims.
     *
     * @var Validator[]
     */
    protected $_validators;

    /**
     * Set of JSON Web Keys usable for the validation.
     *
     * @var JWKSet
     */
    protected $_keys;

    /**
     * Whether to allow unsecured JWT's, that is, claims without integrity
     * protection nor encryption.
     *
     * @var bool
     */
    protected $_allowUnsecured;

    /**
     * Constructor.
     *
     * @param null|array  $constraints Optional array of constraints for the
     *                                 registered claims
     * @param null|JWKSet $keys        Optional set of JSON Web Keys used for
     *                                 signature validation and/or decryption
     */
    public function __construct(?array $constraints = null, ?JWKSet $keys = null)
    {
        $this->_refTime = time();
        $this->_leeway = 60;
        $this->_constraints = $constraints ? $constraints : [];
        $this->_validators = [];
        $this->_keys = $keys ? $keys : new JWKSet();
        $this->_allowUnsecured = false;
    }

    /**
     * Initialize with a single JSON Web Key.
     *
     * @param JWK        $key         JSON Web Key
     * @param null|array $constraints Optional constraints
     *
     * @return self
     */
    public static function fromJWK(JWK $key, ?array $constraints = null): self
    {
        return new self($constraints, new JWKSet($key));
    }

    /**
     * Get self with the reference time.
     *
     * @param null|int $ts Unix timestamp
     *
     * @return self
     */
    public function withReferenceTime(?int $ts): self
    {
        $obj = clone $this;
        $obj->_refTime = $ts;
        return $obj;
    }

    /**
     * Check whether the reference time is set.
     *
     * @return bool
     */
    public function hasReferenceTime(): bool
    {
        return isset($this->_refTime);
    }

    /**
     * Get the reference time.
     *
     * @throws \LogicException
     *
     * @return int
     */
    public function referenceTime(): int
    {
        if (!$this->hasReferenceTime()) {
            throw new \LogicException('Reference time not set.');
        }
        return $this->_refTime;
    }

    /**
     * Get self with the reference time leeway.
     *
     * @param int $seconds
     *
     * @return self
     */
    public function withLeeway(int $seconds): self
    {
        $obj = clone $this;
        $obj->_leeway = $seconds;
        return $obj;
    }

    /**
     * Get the reference time leeway.
     *
     * @return int
     */
    public function leeway(): int
    {
        return $this->_leeway;
    }

    /**
     * Get self with a validation constraint.
     *
     * If the claim does not provide its own validator, an explicit validator
     * must be given.
     *
     * @param string         $name       Claim name
     * @param mixed          $constraint Value to check claim against
     * @param null|Validator $validator  Optional explicit validator
     *
     * @return self
     */
    public function withConstraint(string $name, $constraint,
        ?Validator $validator = null): self
    {
        $obj = clone $this;
        $obj->_constraints[$name] = $constraint;
        if ($validator) {
            $obj->_validators[$name] = $validator;
        }
        return $obj;
    }

    /**
     * Get self with the issuer constraint.
     *
     * @param string $issuer Issuer name
     *
     * @return self
     */
    public function withIssuer(string $issuer): self
    {
        return $this->withConstraint(RegisteredClaim::NAME_ISSUER, $issuer);
    }

    /**
     * Get self with the subject constraint.
     *
     * @param string $subject Subject name
     *
     * @return self
     */
    public function withSubject(string $subject): self
    {
        return $this->withConstraint(RegisteredClaim::NAME_SUBJECT, $subject);
    }

    /**
     * Get self with the audience constraint.
     *
     * @param string $audience Audience name
     *
     * @return self
     */
    public function withAudience(string $audience): self
    {
        return $this->withConstraint(RegisteredClaim::NAME_AUDIENCE, $audience);
    }

    /**
     * Get self with the JWT ID constraint.
     *
     * @param string $id JWT ID
     *
     * @return self
     */
    public function withID(string $id): self
    {
        return $this->withConstraint(RegisteredClaim::NAME_JWT_ID, $id);
    }

    /**
     * Check whether a named constraint is present.
     *
     * @param string $name Claim name
     *
     * @return bool
     */
    public function hasConstraint(string $name): bool
    {
        return isset($this->_constraints[$name]);
    }

    /**
     * Get a constraint value by the claim name.
     *
     * @param string $name Claim name
     *
     * @throws \LogicException If constraint is not set
     *
     * @return mixed Constraint value
     */
    public function constraint(string $name)
    {
        if (!$this->hasConstraint($name)) {
            throw new \LogicException("Constraint {$name} not set.");
        }
        return $this->_constraints[$name];
    }

    /**
     * Check whether a validator is defined for the given claim name.
     *
     * @param string $name Claim name
     *
     * @return bool
     */
    public function hasValidator(string $name): bool
    {
        return isset($this->_validators[$name]);
    }

    /**
     * Get explicitly defined validator by the claim name.
     *
     * @param string $name Claim name
     *
     * @throws \LogicException If validator is not set
     *
     * @return Validator
     */
    public function validator(string $name): Validator
    {
        if (!$this->hasValidator($name)) {
            throw new \LogicException("Validator {$name} not set.");
        }
        return $this->_validators[$name];
    }

    /**
     * Get a set of JSON Web Keys defined in this context.
     *
     * @return JWKSet
     */
    public function keys(): JWKSet
    {
        return $this->_keys;
    }

    /**
     * Get self with 'allow unsecured' flag set.
     *
     * If the unsecured JWT's are allowed, claims shall be considered valid even
     * though they are not signed nor encrypted.
     *
     * @param bool $allow Whether to allow unsecured JWT's
     *
     * @return self
     */
    public function withUnsecuredAllowed(bool $allow): self
    {
        $obj = clone $this;
        $obj->_allowUnsecured = $allow;
        return $obj;
    }

    /**
     * Check whether the unsecured JWT's are allowed.
     *
     * @return bool
     */
    public function isUnsecuredAllowed(): bool
    {
        return $this->_allowUnsecured;
    }

    /**
     * Validate claims.
     *
     * @param Claims $claims
     *
     * @throws ValidationException If any of the claims is not valid
     *
     * @return self
     */
    public function validate(Claims $claims): self
    {
        $claimset = iterator_to_array($claims);
        // validate required constraints
        foreach (array_keys($this->_constraints) as $name) {
            if (!isset($claimset[$name])) {
                throw new ValidationException("Claim '{$name}' is required.");
            }
            if (!$claimset[$name]->validateWithContext($this)) {
                throw new ValidationException(
                    "Validation of claim '{$name}' failed.");
            }
            unset($claimset[$name]);
        }
        // validate remaining claims using default validators
        foreach ($claimset as $name => $claim) {
            if (!$claim->validateWithContext($this)) {
                throw new ValidationException(
                    "Validation of claim '{$name}' failed.");
            }
        }
        return $this;
    }
}
