<?php

namespace JWX\JWT\Claim;


/**
 * Base class for registered claims.
 *
 * @link http://www.iana.org/assignments/jwt/jwt.xhtml
 */
abstract class RegisteredClaim extends Claim
{
	// JWT claims
	const NAME_ISSUER = "iss";
	const NAME_SUBJECT = "sub";
	const NAME_AUDIENCE = "aud";
	const NAME_EXPIRATION_TIME = "exp";
	const NAME_NOT_BEFORE = "nbf";
	const NAME_ISSUED_AT = "iat";
	const NAME_JWT_ID = "jti";
	
	// OpenID claims
	const NAME_FULL_NAME = "name";
	const NAME_GIVEN_NAME = "given_name";
	const NAME_FAMILY_NAME = "family_name";
	const NAME_MIDDLE_NAME = "middle_name";
	const NAME_NICKNAME = "nickname";
	const NAME_PREFERRED_USERNAME = "preferred_username";
	const NAME_PROFILE_URL = "profile";
	const NAME_PICTURE_URL = "picture";
	const NAME_WEBSITE_URL = "website";
	const NAME_EMAIL = "email";
	const NAME_EMAIL_VERIFIED = "email_verified";
	const NAME_GENDER = "gender";
	const NAME_BIRTHDATE = "birthdate";
	const NAME_TIMEZONE = "zoneinfo";
	const NAME_LOCALE = "locale";
	const NAME_PHONE_NUMBER = "phone_number";
	const NAME_PHONE_NUMBER_VERIFIED = "phone_number_verified";
	const NAME_ADDRESS = "address";
	const NAME_UPDATED_AT = "updated_at";
	const NAME_AUTHORIZED_PARTY = "azp";
	const NAME_NONCE = "nonce";
	const NAME_AUTH_TIME = "auth_time";
	const NAME_ACCESS_TOKEN_HASH = "at_hash";
	const NAME_CODE_HASH = "c_hash";
	const NAME_ACR = "acr";
	const NAME_AMR = "amr";
	const NAME_SUB_JWK = "sub_jwk";
	
	/**
	 * Mapping from registered claim name to class name.
	 *
	 * @internal
	 *
	 * @var array
	 */
	const MAP_NAME_TO_CLASS = array(
		/* @formatter:off */
		self::NAME_ISSUER => IssuerClaim::class,
		self::NAME_SUBJECT => SubjectClaim::class,
		self::NAME_AUDIENCE => AudienceClaim::class,
		self::NAME_EXPIRATION_TIME => ExpirationTimeClaim::class,
		self::NAME_NOT_BEFORE => NotBeforeClaim::class,
		self::NAME_ISSUED_AT => IssuedAtClaim::class,
		self::NAME_JWT_ID => JWTIDClaim::class
		/* @formatter:on */
	);
	
	/**
	 * Initialize concrete claim instance from a JSON value.
	 *
	 * @param mixed $value
	 * @return RegisteredClaim
	 */
	public static function fromJSONValue($value) {
		return new static($value);
	}
}
