<?php

namespace JWX\JWT\Claim;


/**
 * Trait for Claims to provide claim accessor methods for typed return values.
 */
trait TypedClaims
{
	/**
	 * Check whether the claim is present.
	 *
	 * @param string $name Claim name
	 * @return bool
	 */
	abstract public function has($name);
	
	/**
	 * Get the claim by name.
	 *
	 * @param string $name Claim name
	 * @return Claim
	 */
	abstract public function get($name);
	
	/**
	 * Check whether the issuer claim is present.
	 *
	 * @return bool
	 */
	public function hasIssuer() {
		return $this->has(RegisteredClaim::NAME_ISSUER);
	}
	
	/**
	 * Get the issuer claim.
	 *
	 * @return IssuerClaim
	 */
	public function issuer() {
		return self::_checkType($this->get(RegisteredClaim::NAME_ISSUER), 
			IssuerClaim::class);
	}
	
	/**
	 * Check whether the subject claim is present.
	 *
	 * @return bool
	 */
	public function hasSubject() {
		return $this->has(RegisteredClaim::NAME_SUBJECT);
	}
	
	/**
	 * Get the subject claim.
	 *
	 * @return SubjectClaim
	 */
	public function subject() {
		return self::_checkType($this->get(RegisteredClaim::NAME_SUBJECT), 
			SubjectClaim::class);
	}
	
	/**
	 * Check whether the audience claim is present.
	 *
	 * @return bool
	 */
	public function hasAudience() {
		return $this->has(RegisteredClaim::NAME_AUDIENCE);
	}
	
	/**
	 * Get the audience claim.
	 *
	 * @return AudienceClaim
	 */
	public function audience() {
		return self::_checkType($this->get(RegisteredClaim::NAME_AUDIENCE), 
			AudienceClaim::class);
	}
	
	/**
	 * Check whether the expiration time claim is present.
	 *
	 * @return bool
	 */
	public function hasExpirationTime() {
		return $this->has(RegisteredClaim::NAME_EXPIRATION_TIME);
	}
	
	/**
	 * Get the expiration time claim.
	 *
	 * @return ExpirationTimeClaim
	 */
	public function expirationTime() {
		return self::_checkType(
			$this->get(RegisteredClaim::NAME_EXPIRATION_TIME), 
			ExpirationTimeClaim::class);
	}
	
	/**
	 * Check whether the not before claim is present.
	 *
	 * @return bool
	 */
	public function hasNotBefore() {
		return $this->has(RegisteredClaim::NAME_NOT_BEFORE);
	}
	
	/**
	 * Get the not before claim.
	 *
	 * @return NotBeforeClaim
	 */
	public function notBefore() {
		return self::_checkType($this->get(RegisteredClaim::NAME_NOT_BEFORE), 
			NotBeforeClaim::class);
	}
	
	/**
	 * Check whether the issued at claim is present.
	 *
	 * @return bool
	 */
	public function hasIssuedAt() {
		return $this->has(RegisteredClaim::NAME_ISSUED_AT);
	}
	
	/**
	 * Get the issued at claim.
	 *
	 * @return IssuedAtClaim
	 */
	public function issuedAt() {
		return self::_checkType($this->get(RegisteredClaim::NAME_ISSUED_AT), 
			IssuedAtClaim::class);
	}
	
	/**
	 * Check whether the JWT ID claim is present.
	 *
	 * @return bool
	 */
	public function hasJWTID() {
		return $this->has(RegisteredClaim::NAME_JWT_ID);
	}
	
	/**
	 * Get the JWT ID claim.
	 *
	 * @return JWTIDClaim
	 */
	public function JWTID() {
		return self::_checkType($this->get(RegisteredClaim::NAME_JWT_ID), 
			JWTIDClaim::class);
	}
	
	/**
	 * Check that the claim is an instance of the given class.
	 *
	 * @param Claim $claim Claim object
	 * @param string $cls Class name
	 * @throws \UnexpectedValueException
	 * @return Claim
	 */
	private static function _checkType(Claim $claim, $cls) {
		if (!$claim instanceof $cls) {
			throw new \UnexpectedValueException(
				"$cls expected, got " . get_class($claim));
		}
		return $claim;
	}
}
