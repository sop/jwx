<?php

namespace JWX\JWT;

use JWX\JWK\JWK;
use JWX\JWK\JWKSet;
use JWX\JWT\Claim\RegisteredClaim;
use JWX\JWT\Exception\ValidationException;


/**
 * Class to provide context for claims validation.
 *
 * Validation constraints are variables, that are compared against the claims.
 * Context also provides a set of JSON Web Keys, that shall be used for the
 * JWS signature validation, or JWE payload decryption.
 */
class ValidationContext
{
	/**
	 * Reference time.
	 *
	 * @var int $_refTime
	 */
	protected $_refTime;
	
	/**
	 * Leeway in seconds for the reference time constraints.
	 *
	 * @var int $_leeway
	 */
	protected $_leeway;
	
	/**
	 * Validation constraints.
	 *
	 * @var array $_constraints
	 */
	protected $_constraints;
	
	/**
	 * Set of JSON Web Keys usable for the validation.
	 *
	 * @var JWKSet $_keys
	 */
	protected $_keys;
	
	/**
	 * Whether to allow unsecured JWT's, that is, claims without integrity
	 * protection nor encryption.
	 *
	 * @var bool $_allowUnsecured
	 */
	protected $_allowUnsecured;
	
	/**
	 * Constructor.
	 *
	 * @param array $constraints Optional array of constraints keyed by claim
	 *        names
	 * @param JWKSet $keys Optional set of JSON Web Keys used for signature
	 *        validation and/or decryption
	 */
	public function __construct(array $constraints = null, JWKSet $keys = null) {
		$this->_refTime = time();
		$this->_leeway = 60;
		$this->_constraints = $constraints ? $constraints : [];
		$this->_keys = $keys ? $keys : new JWKSet();
		$this->_allowUnsecured = false;
	}
	
	/**
	 * Initialize with a single JSON Web Key.
	 *
	 * @param JWK $key JSON Web Key
	 * @param array $constraints Optional constraints
	 * @return self
	 */
	public static function fromJWK(JWK $key, array $constraints = null) {
		return new self($constraints, new JWKSet($key));
	}
	
	/**
	 * Get self with the reference time.
	 *
	 * @param int|null $ts Unix timestamp
	 * @return self
	 */
	public function withReferenceTime($ts) {
		$obj = clone $this;
		$obj->_refTime = $ts;
		return $obj;
	}
	
	/**
	 * Check whether the reference time is set.
	 *
	 * @return bool
	 */
	public function hasReferenceTime() {
		return isset($this->_refTime);
	}
	
	/**
	 * Get the reference time.
	 *
	 * @throws \LogicException
	 * @return int
	 */
	public function referenceTime() {
		if (!$this->hasReferenceTime()) {
			throw new \LogicException("Reference time not set.");
		}
		return $this->_refTime;
	}
	
	/**
	 * Get self with the reference time leeway.
	 *
	 * @param int $seconds
	 * @return self
	 */
	public function withLeeway($seconds) {
		$obj = clone $this;
		$obj->_leeway = $seconds;
		return $obj;
	}
	
	/**
	 * Get the reference time leeway.
	 *
	 * @return int
	 */
	public function leeway() {
		return $this->_leeway;
	}
	
	/**
	 * Get self with a validation constraint.
	 *
	 * @param string $name Claim name
	 * @param mixed $constraint Value to check claim against
	 * @return self
	 */
	public function withConstraint($name, $constraint) {
		$obj = clone $this;
		$obj->_constraints[$name] = $constraint;
		return $obj;
	}
	
	/**
	 * Get self with the issuer constraint.
	 *
	 * @param string $issuer
	 * @return self
	 */
	public function withIssuer($issuer) {
		return $this->withConstraint(RegisteredClaim::NAME_ISSUER, $issuer);
	}
	
	/**
	 * Get self with the subject constraint.
	 *
	 * @param string $subject
	 * @return self
	 */
	public function withSubject($subject) {
		return $this->withConstraint(RegisteredClaim::NAME_SUBJECT, $subject);
	}
	
	/**
	 * Get self with the audience constraint.
	 *
	 * @param string $audience
	 * @return self
	 */
	public function withAudience($audience) {
		return $this->withConstraint(RegisteredClaim::NAME_AUDIENCE, $audience);
	}
	
	/**
	 * Get self with the JWT ID constraint.
	 *
	 * @param string $id
	 * @return self
	 */
	public function withID($id) {
		return $this->withConstraint(RegisteredClaim::NAME_JWT_ID, $id);
	}
	
	/**
	 * Check whether a named constraint is present.
	 *
	 * @param string $name Claim name
	 * @return bool
	 */
	public function hasConstraint($name) {
		return isset($this->_constraints[$name]);
	}
	
	/**
	 * Get a constraint value by the claim name.
	 *
	 * @param string $name Claim name
	 * @throws \LogicException If constraint is not set
	 * @return mixed Constraint value
	 */
	public function constraint($name) {
		if (!$this->hasConstraint($name)) {
			throw new \LogicException("Constraint $name not set.");
		}
		return $this->_constraints[$name];
	}
	
	/**
	 * Get a set of JSON Web Keys defined in this context.
	 *
	 * @return JWKSet
	 */
	public function keys() {
		return $this->_keys;
	}
	
	/**
	 * Get self with 'allow unsecured' flag set.
	 *
	 * If the unsecured JWT's are allowed, claims shall be considered valid even
	 * though they are not signed nor encrypted.
	 *
	 * @param bool $allow Whether to allow unsecured JWT's
	 * @return self
	 */
	public function withUnsecuredAllowed($allow) {
		$obj = clone $this;
		$obj->_allowUnsecured = (bool) $allow;
		return $obj;
	}
	
	/**
	 * Check whether the unsecured JWT's are allowed.
	 *
	 * @return bool
	 */
	public function isUnsecuredAllowed() {
		return $this->_allowUnsecured;
	}
	
	/**
	 * Validate claims.
	 *
	 * @param Claims $claims
	 * @throws ValidationException If any of the claims is not valid
	 * @return self
	 */
	public function validate(Claims $claims) {
		foreach ($claims as $claim) {
			if (!$claim->validateWithContext($this)) {
				throw new ValidationException(
					"Validation of claim '" . $claim->name() . "' failed.");
			}
		}
		return $this;
	}
}
