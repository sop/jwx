<?php

declare(strict_types = 1);

namespace Sop\JWX\JWT\Claim;

/**
 * Base class for registered claims.
 *
 * @see http://www.iana.org/assignments/jwt/jwt.xhtml
 */
abstract class RegisteredClaim extends Claim
{
    // JWT claims
    public const NAME_ISSUER = 'iss';
    public const NAME_SUBJECT = 'sub';
    public const NAME_AUDIENCE = 'aud';
    public const NAME_EXPIRATION_TIME = 'exp';
    public const NAME_NOT_BEFORE = 'nbf';
    public const NAME_ISSUED_AT = 'iat';
    public const NAME_JWT_ID = 'jti';

    // OpenID claims
    public const NAME_FULL_NAME = 'name';
    public const NAME_GIVEN_NAME = 'given_name';
    public const NAME_FAMILY_NAME = 'family_name';
    public const NAME_MIDDLE_NAME = 'middle_name';
    public const NAME_NICKNAME = 'nickname';
    public const NAME_PREFERRED_USERNAME = 'preferred_username';
    public const NAME_PROFILE_URL = 'profile';
    public const NAME_PICTURE_URL = 'picture';
    public const NAME_WEBSITE_URL = 'website';
    public const NAME_EMAIL = 'email';
    public const NAME_EMAIL_VERIFIED = 'email_verified';
    public const NAME_GENDER = 'gender';
    public const NAME_BIRTHDATE = 'birthdate';
    public const NAME_TIMEZONE = 'zoneinfo';
    public const NAME_LOCALE = 'locale';
    public const NAME_PHONE_NUMBER = 'phone_number';
    public const NAME_PHONE_NUMBER_VERIFIED = 'phone_number_verified';
    public const NAME_ADDRESS = 'address';
    public const NAME_UPDATED_AT = 'updated_at';
    public const NAME_AUTHORIZED_PARTY = 'azp';
    public const NAME_NONCE = 'nonce';
    public const NAME_AUTH_TIME = 'auth_time';
    public const NAME_ACCESS_TOKEN_HASH = 'at_hash';
    public const NAME_CODE_HASH = 'c_hash';
    public const NAME_ACR = 'acr';
    public const NAME_AMR = 'amr';
    public const NAME_SUB_JWK = 'sub_jwk';

    /**
     * Mapping from registered claim name to class name.
     *
     * @internal
     *
     * @var array
     */
    public const MAP_NAME_TO_CLASS = [
        self::NAME_ISSUER => IssuerClaim::class,
        self::NAME_SUBJECT => SubjectClaim::class,
        self::NAME_AUDIENCE => AudienceClaim::class,
        self::NAME_EXPIRATION_TIME => ExpirationTimeClaim::class,
        self::NAME_NOT_BEFORE => NotBeforeClaim::class,
        self::NAME_ISSUED_AT => IssuedAtClaim::class,
        self::NAME_JWT_ID => JWTIDClaim::class,
    ];

    /**
     * Constructor.
     *
     * Defined here for type strictness. Parameters are passed to the
     * superclass.
     *
     * @param mixed ...$args
     */
    public function __construct(...$args)
    {
        parent::__construct((string) $args[0], $args[1],
            isset($args[2]) ? $args[2] : null);
    }

    /**
     * Initialize concrete claim instance from a JSON value.
     *
     * @param mixed $value
     */
    public static function fromJSONValue($value): RegisteredClaim
    {
        return new static($value);
    }
}
