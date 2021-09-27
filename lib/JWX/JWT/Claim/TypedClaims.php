<?php

declare(strict_types = 1);

namespace Sop\JWX\JWT\Claim;

/**
 * Trait for Claims to provide claim accessor methods for typed return values.
 */
trait TypedClaims
{
    /**
     * Check whether the claim is present.
     *
     * @param string $name Claim name
     */
    abstract public function has(string $name): bool;

    /**
     * Get the claim by name.
     *
     * @param string $name Claim name
     */
    abstract public function get(string $name): Claim;

    /**
     * Check whether the issuer claim is present.
     */
    public function hasIssuer(): bool
    {
        return $this->has(RegisteredClaim::NAME_ISSUER);
    }

    /**
     * Get the issuer claim.
     */
    public function issuer(): IssuerClaim
    {
        return self::_checkType($this->get(RegisteredClaim::NAME_ISSUER),
            IssuerClaim::class);
    }

    /**
     * Check whether the subject claim is present.
     */
    public function hasSubject(): bool
    {
        return $this->has(RegisteredClaim::NAME_SUBJECT);
    }

    /**
     * Get the subject claim.
     */
    public function subject(): SubjectClaim
    {
        return self::_checkType($this->get(RegisteredClaim::NAME_SUBJECT),
            SubjectClaim::class);
    }

    /**
     * Check whether the audience claim is present.
     */
    public function hasAudience(): bool
    {
        return $this->has(RegisteredClaim::NAME_AUDIENCE);
    }

    /**
     * Get the audience claim.
     */
    public function audience(): AudienceClaim
    {
        return self::_checkType($this->get(RegisteredClaim::NAME_AUDIENCE),
            AudienceClaim::class);
    }

    /**
     * Check whether the expiration time claim is present.
     */
    public function hasExpirationTime(): bool
    {
        return $this->has(RegisteredClaim::NAME_EXPIRATION_TIME);
    }

    /**
     * Get the expiration time claim.
     */
    public function expirationTime(): ExpirationTimeClaim
    {
        return self::_checkType(
            $this->get(RegisteredClaim::NAME_EXPIRATION_TIME),
            ExpirationTimeClaim::class);
    }

    /**
     * Check whether the not before claim is present.
     */
    public function hasNotBefore(): bool
    {
        return $this->has(RegisteredClaim::NAME_NOT_BEFORE);
    }

    /**
     * Get the not before claim.
     */
    public function notBefore(): NotBeforeClaim
    {
        return self::_checkType($this->get(RegisteredClaim::NAME_NOT_BEFORE),
            NotBeforeClaim::class);
    }

    /**
     * Check whether the issued at claim is present.
     */
    public function hasIssuedAt(): bool
    {
        return $this->has(RegisteredClaim::NAME_ISSUED_AT);
    }

    /**
     * Get the issued at claim.
     */
    public function issuedAt(): IssuedAtClaim
    {
        return self::_checkType($this->get(RegisteredClaim::NAME_ISSUED_AT),
            IssuedAtClaim::class);
    }

    /**
     * Check whether the JWT ID claim is present.
     */
    public function hasJWTID(): bool
    {
        return $this->has(RegisteredClaim::NAME_JWT_ID);
    }

    /**
     * Get the JWT ID claim.
     */
    public function JWTID(): JWTIDClaim
    {
        return self::_checkType($this->get(RegisteredClaim::NAME_JWT_ID),
            JWTIDClaim::class);
    }

    /**
     * Check that the claim is an instance of the given class.
     *
     * @param Claim  $claim Claim object
     * @param string $cls   Class name
     *
     * @throws \UnexpectedValueException
     */
    private static function _checkType(Claim $claim, string $cls): Claim
    {
        if (!$claim instanceof $cls) {
            throw new \UnexpectedValueException(
                "{$cls} expected, got " . get_class($claim));
        }
        return $claim;
    }
}
