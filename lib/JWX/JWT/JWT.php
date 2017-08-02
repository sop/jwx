<?php

namespace JWX\JWT;

use JWX\JWE\CompressionAlgorithm;
use JWX\JWE\ContentEncryptionAlgorithm;
use JWX\JWE\JWE;
use JWX\JWE\KeyManagementAlgorithm;
use JWX\JWK\JWKSet;
use JWX\JWS\JWS;
use JWX\JWS\SignatureAlgorithm;
use JWX\JWS\Algorithm\NoneAlgorithm;
use JWX\JWT\Exception\ValidationException;
use JWX\JWT\Header\Header;
use JWX\JWT\Header\JOSE;
use JWX\JWT\Parameter\ContentTypeParameter;
use JWX\Util\Base64;

/**
 * Represents a token as a JWS or a JWE compact serialization with claims
 * as a payload.
 *
 * @link https://tools.ietf.org/html/rfc7519#section-3
 */
class JWT
{
    /**
     * Type identifier for the signed JWT.
     *
     * @internal
     *
     * @var int
     */
    const TYPE_JWS = 0;
    
    /**
     * Type identifier for the encrypted JWT.
     *
     * @internal
     *
     * @var int
     */
    const TYPE_JWE = 1;
    
    /**
     * JWT parts.
     *
     * @var string[] $_parts
     */
    protected $_parts;
    
    /**
     * JWT type.
     *
     * @var int $_type
     */
    protected $_type;
    
    /**
     * Constructor.
     *
     * @param string $token JWT string
     * @throws \UnexpectedValueException
     */
    public function __construct($token)
    {
        $this->_parts = explode(".", $token);
        switch (count($this->_parts)) {
            case 3:
                $this->_type = self::TYPE_JWS;
                break;
            case 5:
                $this->_type = self::TYPE_JWE;
                break;
            default:
                throw new \UnexpectedValueException("Not a JWT token.");
        }
    }
    
    /**
     * Convert claims set to an unsecured JWT.
     *
     * Unsecured JWT is not signed nor encrypted neither integrity protected,
     * and should thus be handled with care!
     *
     * @link https://tools.ietf.org/html/rfc7519#section-6
     * @param Claims $claims Claims set
     * @param Header|null $header Optional header
     * @throws \RuntimeException For generic errors
     * @return self
     */
    public static function unsecuredFromClaims(Claims $claims,
        Header $header = null)
    {
        return self::signedFromClaims($claims, new NoneAlgorithm(), $header);
    }
    
    /**
     * Convert claims set to a signed JWS token.
     *
     * @param Claims $claims Claims set
     * @param SignatureAlgorithm $algo Signature algorithm
     * @param Header|null $header Optional header
     * @throws \RuntimeException For generic errors
     * @return self
     */
    public static function signedFromClaims(Claims $claims,
        SignatureAlgorithm $algo, Header $header = null)
    {
        $payload = $claims->toJSON();
        $jws = JWS::sign($payload, $algo, $header);
        return new self($jws->toCompact());
    }
    
    /**
     * Convert claims set to an encrypted JWE token.
     *
     * @param Claims $claims Claims set
     * @param KeyManagementAlgorithm $key_algo Key management algorithm
     * @param ContentEncryptionAlgorithm $enc_algo Content encryption algorithm
     * @param CompressionAlgorithm|null $zip_algo Optional compression algorithm
     * @param Header|null $header Optional header
     * @throws \RuntimeException For generic errors
     * @return self
     */
    public static function encryptedFromClaims(Claims $claims,
        KeyManagementAlgorithm $key_algo, ContentEncryptionAlgorithm $enc_algo,
        CompressionAlgorithm $zip_algo = null, Header $header = null)
    {
        $payload = $claims->toJSON();
        $jwe = JWE::encrypt($payload, $key_algo, $enc_algo, $zip_algo, $header);
        return new self($jwe->toCompact());
    }
    
    /**
     * Get claims from the JWT.
     *
     * Claims shall be validated according to given validation context.
     * Validation context must contain all the necessary keys for the signature
     * validation and/or content decryption.
     *
     * If validation context contains only one key, it shall be used explicitly.
     * If multiple keys are provided, they must contain a JWK ID parameter for
     * the key identification.
     *
     * @param ValidationContext $ctx
     * @throws ValidationException If signature is invalid, or decryption fails,
     *         or claims validation fails.
     * @throws \RuntimeException For generic errors
     * @return Claims
     */
    public function claims(ValidationContext $ctx)
    {
        // check signature or decrypt depending on the JWT type.
        if ($this->isJWS()) {
            $payload = self::_validatedPayloadFromJWS($this->JWS(), $ctx);
        } else {
            $payload = self::_validatedPayloadFromJWE($this->JWE(), $ctx);
        }
        // if JWT contains a nested token
        if ($this->isNested()) {
            return $this->_claimsFromNestedPayload($payload, $ctx);
        }
        // decode claims and validate
        $claims = Claims::fromJSON($payload);
        $ctx->validate($claims);
        return $claims;
    }
    
    /**
     * Sign self producing a nested JWT.
     *
     * Note that if JWT is to be signed and encrypted, it should be done in
     * sign-then-encrypt order. Please refer to links for security information.
     *
     * @link https://tools.ietf.org/html/rfc7519#section-11.2
     * @param SignatureAlgorithm $algo Signature algorithm
     * @param Header|null $header Optional header
     * @throws \RuntimeException For generic errors
     * @return self
     */
    public function signNested(SignatureAlgorithm $algo, Header $header = null)
    {
        if (!isset($header)) {
            $header = new Header();
        }
        // add JWT content type parameter
        $header = $header->withParameters(
            new ContentTypeParameter(ContentTypeParameter::TYPE_JWT));
        $jws = JWS::sign($this->token(), $algo, $header);
        return new self($jws->toCompact());
    }
    
    /**
     * Encrypt self producing a nested JWT.
     *
     * This JWT should be a JWS, that is, the order of nesting should be
     * sign-then-encrypt.
     *
     * @link https://tools.ietf.org/html/rfc7519#section-11.2
     * @param KeyManagementAlgorithm $key_algo Key management algorithm
     * @param ContentEncryptionAlgorithm $enc_algo Content encryption algorithm
     * @param CompressionAlgorithm|null $zip_algo Optional compression algorithm
     * @param Header|null $header Optional header
     * @throws \RuntimeException For generic errors
     * @return self
     */
    public function encryptNested(KeyManagementAlgorithm $key_algo,
        ContentEncryptionAlgorithm $enc_algo,
        CompressionAlgorithm $zip_algo = null, Header $header = null)
    {
        if (!isset($header)) {
            $header = new Header();
        }
        // add JWT content type parameter
        $header = $header->withParameters(
            new ContentTypeParameter(ContentTypeParameter::TYPE_JWT));
        $jwe = JWE::encrypt($this->token(), $key_algo, $enc_algo, $zip_algo,
            $header);
        return new self($jwe->toCompact());
    }
    
    /**
     * Whether JWT is a JWS.
     *
     * @return bool
     */
    public function isJWS()
    {
        return $this->_type == self::TYPE_JWS;
    }
    
    /**
     * Get JWT as a JWS.
     *
     * @throws \LogicException
     * @return JWS
     */
    public function JWS()
    {
        if (!$this->isJWS()) {
            throw new \LogicException("Not a JWS.");
        }
        return JWS::fromParts($this->_parts);
    }
    
    /**
     * Whether JWT is a JWE.
     *
     * @return bool
     */
    public function isJWE()
    {
        return $this->_type == self::TYPE_JWE;
    }
    
    /**
     * Get JWT as a JWE.
     *
     * @throws \LogicException
     * @return JWE
     */
    public function JWE()
    {
        if (!$this->isJWE()) {
            throw new \LogicException("Not a JWE.");
        }
        return JWE::fromParts($this->_parts);
    }
    
    /**
     * Check whether JWT contains another nested JWT.
     *
     * @return bool
     */
    public function isNested()
    {
        $header = $this->header();
        if (!$header->hasContentType()) {
            return false;
        }
        $cty = $header->contentType()->value();
        if ($cty != ContentTypeParameter::TYPE_JWT) {
            return false;
        }
        return true;
    }
    
    /**
     * Check whether JWT is unsecured, that is, it's neither integrity protected
     * nor encrypted.
     *
     * @return bool
     */
    public function isUnsecured()
    {
        // encrypted JWT shall be considered secure
        if ($this->isJWE()) {
            return false;
        }
        // check whether JWS is unsecured
        return $this->JWS()->isUnsecured();
    }
    
    /**
     * Get JWT header.
     *
     * @return JOSE
     */
    public function header()
    {
        $header = Header::fromJSON(Base64::urlDecode($this->_parts[0]));
        return new JOSE($header);
    }
    
    /**
     * Get JWT as a string.
     *
     * @return string
     */
    public function token()
    {
        return implode(".", $this->_parts);
    }
    
    /**
     * Get claims from a nested payload.
     *
     * @param string $payload JWT payload
     * @param ValidationContext $ctx Validation context
     * @return Claims
     */
    private function _claimsFromNestedPayload($payload, ValidationContext $ctx)
    {
        $jwt = new JWT($payload);
        // if this token secured, allow nested tokens to be unsecured.
        if (!$this->isUnsecured()) {
            $ctx = $ctx->withUnsecuredAllowed(true);
        }
        return $jwt->claims($ctx);
    }
    
    /**
     * Get validated payload from JWS.
     *
     * @param JWS $jws JWS
     * @param ValidationContext $ctx Validation context
     * @throws ValidationException If signature validation fails
     * @return string
     */
    private static function _validatedPayloadFromJWS(JWS $jws,
        ValidationContext $ctx)
    {
        // if JWS is unsecured
        if ($jws->isUnsecured()) {
            return self::_validatedPayloadFromUnsecuredJWS($jws, $ctx);
        }
        return self::_validatedPayloadFromSignedJWS($jws, $ctx->keys());
    }
    
    /**
     * Get validated payload from an unsecured JWS.
     *
     * @param JWS $jws JWS
     * @param ValidationContext $ctx Validation context
     * @throws ValidationException If unsecured JWT's are not allowed, or JWS
     *         token is malformed
     * @return string
     */
    private static function _validatedPayloadFromUnsecuredJWS(JWS $jws,
        ValidationContext $ctx)
    {
        if (!$ctx->isUnsecuredAllowed()) {
            throw new ValidationException("Unsecured JWS not allowed.");
        }
        if (!$jws->validate(new NoneAlgorithm())) {
            throw new ValidationException("Malformed unsecured token.");
        }
        return $jws->payload();
    }
    
    /**
     * Get validated payload from a signed JWS.
     *
     * @param JWS $jws JWS
     * @param JWKSet $keys Set of allowed keys for the signature validation
     * @throws ValidationException If validation fails
     * @return string
     */
    private static function _validatedPayloadFromSignedJWS(JWS $jws, JWKSet $keys)
    {
        try {
            // explicitly defined key
            if (1 == count($keys)) {
                $valid = $jws->validateWithJWK($keys->first());
            } else {
                $valid = $jws->validateWithJWKSet($keys);
            }
        } catch (\RuntimeException $e) {
            throw new ValidationException("JWS validation failed.", null, $e);
        }
        if (!$valid) {
            throw new ValidationException("JWS signature is invalid.");
        }
        return $jws->payload();
    }
    
    /**
     * Get validated payload from an encrypted JWE.
     *
     * @param JWE $jwe JWE
     * @param ValidationContext $ctx Validation context
     * @throws ValidationException If decryption fails
     * @return string
     */
    private static function _validatedPayloadFromJWE(JWE $jwe,
        ValidationContext $ctx)
    {
        try {
            $keys = $ctx->keys();
            // explicitly defined key
            if (1 == count($keys)) {
                return $jwe->decryptWithJWK($keys->first());
            }
            return $jwe->decryptWithJWKSet($keys);
        } catch (\RuntimeException $e) {
            throw new ValidationException("JWE validation failed.", null, $e);
        }
    }
    
    /**
     * Convert JWT to string.
     *
     * @return string
     */
    public function __toString()
    {
        return $this->token();
    }
}
