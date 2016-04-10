<?php

namespace JWX\JWT;

use JWX\JWT\Claim\RegisteredClaim;


class ValidationContext
{
	/**
	 * Reference time
	 *
	 * @var int $_refTime
	 */
	protected $_refTime;
	
	/**
	 * Validation constraints
	 *
	 * @var string $_constraints
	 */
	protected $_constraints;
	
	/**
	 * Constructor
	 */
	public function __construct() {
		$this->_refTime = time();
		$this->_constraints = array();
	}
	
	/**
	 * Get self with reference time
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
	 * Whether reference time is set
	 *
	 * @return bool
	 */
	public function hasReferenceTime() {
		return isset($this->_refTime);
	}
	
	/**
	 * Get reference time
	 *
	 * @throws \LogicException
	 * @return int
	 */
	public function referenceTime() {
		if (!$this->hasReferenceTime()) {
			throw new \LogicException("Reference time not set");
		}
		return $this->_refTime;
	}
	
	/**
	 * Get self with validation constraint
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
	 * Get self with issuer constraint
	 *
	 * @param string $issuer
	 * @return self
	 */
	public function withIssuer($issuer) {
		return $this->withConstraint(RegisteredClaim::NAME_ISSUER, $issuer);
	}
	
	/**
	 * Get self with subject constraint
	 *
	 * @param string $subject
	 * @return self
	 */
	public function withSubject($subject) {
		return $this->withConstraint(RegisteredClaim::NAME_SUBJECT, $subject);
	}
	
	/**
	 * Get self with audience constraint
	 *
	 * @param string $audience
	 * @return self
	 */
	public function withAudience($audience) {
		return $this->withConstraint(RegisteredClaim::NAME_AUDIENCE, $audience);
	}
	
	/**
	 * Get self with JWT ID constraint
	 *
	 * @param string $id
	 * @return self
	 */
	public function withID($id) {
		return $this->withConstraint(RegisteredClaim::NAME_JWT_ID, $id);
	}
	
	/**
	 * Whether constraint is present
	 *
	 * @param string $name Claim name
	 * @return bool
	 */
	public function hasConstraint($name) {
		return isset($this->_constraints[$name]);
	}
	
	/**
	 * Get constraint by claim name
	 *
	 * @param string $name
	 * @throws \LogicException
	 * @return mixed Constraint value
	 */
	public function constraint($name) {
		if (!$this->hasConstraint($name)) {
			throw new \LogicException("Constraint $name not set");
		}
		return $this->_constraints[$name];
	}
	
	/**
	 * Validate claims
	 *
	 * @param Claims $claims
	 * @throws \RuntimeException If any of the claims is not valid
	 * @return self
	 */
	public function validate(Claims $claims) {
		foreach ($claims as $claim) {
			if (!$claim->validate($this)) {
				throw new \RuntimeException(
					"Validation of claim '" . $claim->name() . "' failed");
			}
		}
		return $this;
	}
}
