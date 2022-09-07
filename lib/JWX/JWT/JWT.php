<?php

declare(strict_types = 1);

namespace Sop\JWX\JWT;

use Sop\JWX\JWE\CompressionAlgorithm;
use Sop\JWX\JWE\ContentEncryptionAlgorithm;
use Sop\JWX\JWE\JWE;
use Sop\JWX\JWE\KeyManagementAlgorithm;
use Sop\JWX\JWK\JWKSet;
use Sop\JWX\JWS\Algorithm\NoneAlgorithm;
use Sop\JWX\JWS\JWS;
use Sop\JWX\JWS\SignatureAlgorithm;
use Sop\JWX\JWT\Exception\ValidationException;
use Sop\JWX\JWT\Header\Header;
use Sop\JWX\JWT\Header\JOSE;
use Sop\JWX\JWT\Parameter\ContentTypeParameter;
use Sop\JWX\Parameter\Parameter;
use Sop\JWX\Util\Base64;

/**
 * Represents a token as a JWS or a JWE compact serialization with claims
 * as a payload.
 *
 * @see https://tools.ietf.org/html/rfc7519#section-3
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
    public const TYPE_JWS = 0;

    /**
     * Type identifier for the encrypted JWT.
     *
     * @internal
     *
     * @var int
     */
    public const TYPE_JWE = 1;

    /**
     * JWT parts.
     *
     * @var string[]
     */
    protected $_parts;

    /**
     * JWT type.
     *
     * @var int
     */
    protected $_type;

    /**
     * Constructor.
     *
     * @param string $token JWT string
     *
     * @throws \UnexpectedValueException
     */
    public function __construct(string $token)
    {
        $this->_parts = explode('.', $token);
        switch (count($this->_parts)) {
            case 3:
                $this->_type = self::TYPE_JWS;
                break;
            case 5:
                $this->_type = self::TYPE_JWE;
                break;
            default:
                throw new \UnexpectedValueException('Not a JWT token.');
        }
    }

    /**
     * Convert JWT to string.
     */
    public function __toString(): string
    {
        return $this->token();
    }

    /**
     * Convert claims set to an unsecured JWT.
     *
     * Unsecured JWT is not signed nor encrypted neither integrity protected,
     * and should thus be handled with care!
     *
     * @see https://tools.ietf.org/html/rfc7519#section-6
     *
     * @param Claims      $claims Claims set
     * @param null|Header $header Optional header
     *
     * @throws \RuntimeException For generic errors
     */
    public static function unsecuredFromClaims(Claims $claims,
        ?Header $header = null): self
    {
        return self::signedFromClaims($claims, new NoneAlgorithm(), $header);
    }

    /**
     * Convert claims set to a signed JWS token.
     *
     * @param Claims             $claims Claims set
     * @param SignatureAlgorithm $algo   Signature algorithm
     * @param null|Header        $header Optional header
     *
     * @throws \RuntimeException For generic errors
     */
    public static function signedFromClaims(Claims $claims,
        SignatureAlgorithm $algo, ?Header $header = null): self
    {
        $payload = $claims->toJSON();
        $jws = JWS::sign($payload, $algo, $header);
        return new self($jws->toCompact());
    }

    /**
     * Convert claims set to an encrypted JWE token.
     *
     * @param Claims                     $claims   Claims set
     * @param KeyManagementAlgorithm     $key_algo Key management algorithm
     * @param ContentEncryptionAlgorithm $enc_algo Content encryption algorithm
     * @param null|CompressionAlgorithm  $zip_algo Optional compression algorithm
     * @param null|Header                $header   Optional header
     *
     * @throws \RuntimeException For generic errors
     */
    public static function encryptedFromClaims(Claims $claims,
        KeyManagementAlgorithm $key_algo, ContentEncryptionAlgorithm $enc_algo,
        ?CompressionAlgorithm $zip_algo = null, ?Header $header = null): self
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
     * @throws ValidationException if signature is invalid, or decryption fails,
     *                             or claims validation fails
     * @throws \RuntimeException   For generic errors
     */
    public function claims(ValidationContext $ctx): Claims
    {
        // check that the token uses only permitted algorithms
        $this->_validateAlgorithms($ctx);
        // check signature or decrypt depending on the JWT type
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
     * @see https://tools.ietf.org/html/rfc7519#section-11.2
     *
     * @param SignatureAlgorithm $algo   Signature algorithm
     * @param null|Header        $header Optional header
     *
     * @throws \RuntimeException For generic errors
     */
    public function signNested(SignatureAlgorithm $algo, ?Header $header = null): self
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
     * @see https://tools.ietf.org/html/rfc7519#section-11.2
     *
     * @param KeyManagementAlgorithm     $key_algo Key management algorithm
     * @param ContentEncryptionAlgorithm $enc_algo Content encryption algorithm
     * @param null|CompressionAlgorithm  $zip_algo Optional compression algorithm
     * @param null|Header                $header   Optional header
     *
     * @throws \RuntimeException For generic errors
     */
    public function encryptNested(KeyManagementAlgorithm $key_algo,
        ContentEncryptionAlgorithm $enc_algo,
        ?CompressionAlgorithm $zip_algo = null, ?Header $header = null): self
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
     */
    public function isJWS(): bool
    {
        return self::TYPE_JWS === $this->_type;
    }

    /**
     * Get JWT as a JWS.
     *
     * @throws \LogicException
     */
    public function JWS(): JWS
    {
        if (!$this->isJWS()) {
            throw new \LogicException('Not a JWS.');
        }
        return JWS::fromParts($this->_parts);
    }

    /**
     * Whether JWT is a JWE.
     */
    public function isJWE(): bool
    {
        return self::TYPE_JWE === $this->_type;
    }

    /**
     * Get JWT as a JWE.
     *
     * @throws \LogicException
     */
    public function JWE(): JWE
    {
        if (!$this->isJWE()) {
            throw new \LogicException('Not a JWE.');
        }
        return JWE::fromParts($this->_parts);
    }

    /**
     * Check whether JWT contains another nested JWT.
     */
    public function isNested(): bool
    {
        $header = $this->header();
        if (!$header->hasContentType()) {
            return false;
        }
        $cty = $header->contentType()->value();
        if (ContentTypeParameter::TYPE_JWT !== $cty) {
            return false;
        }
        return true;
    }

    /**
     * Check whether JWT is unsecured, that is, it's neither integrity protected
     * nor encrypted.
     */
    public function isUnsecured(): bool
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
     */
    public function header(): JOSE
    {
        $header = Header::fromJSON(Base64::urlDecode($this->_parts[0]));
        return new JOSE($header);
    }

    /**
     * Get JWT as a string.
     */
    public function token(): string
    {
        return implode('.', $this->_parts);
    }

    /**
     * Get claims from a nested payload.
     *
     * @param string            $payload JWT payload
     * @param ValidationContext $ctx     Validation context
     */
    private function _claimsFromNestedPayload(string $payload,
        ValidationContext $ctx): Claims
    {
        $jwt = new JWT($payload);
        // if this token secured, allow nested tokens to be unsecured.
        if (!$this->isUnsecured()) {
            $ctx = $ctx->withUnsecuredAllowed(true);
        }
        return $jwt->claims($ctx);
    }

    /**
     * Validate that the token uses only permitted algorithms.
     *
     * @param ValidationContext $ctx Validation context
     */
    private function _validateAlgorithms(ValidationContext $ctx): void
    {
        $headers = $this->header();
        if ($headers->hasAlgorithm()) {
            $this->_validateAlgorithmParameter($headers->algorithm(), $ctx);
        }
        if ($headers->hasEncryptionAlgorithm()) {
            $this->_validateAlgorithmParameter($headers->encryptionAlgorithm(), $ctx);
        }
        if ($headers->hasCompressionAlgorithm()) {
            $this->_validateAlgorithmParameter($headers->compressionAlgorithm(), $ctx);
        }
    }

    /**
     * Check that given algorithm parameter value is permitted.
     *
     * @param Parameter         $param Header parameter
     * @param ValidationContext $ctx   Validation context
     *
     * @throws ValidationException If algorithm is prohibited
     */
    private function _validateAlgorithmParameter(Parameter $param,
        ValidationContext $ctx): void
    {
        if (!$ctx->isPermittedAlgorithm($param->value())) {
            throw new ValidationException(sprintf(
                '%s algorithm %s is not permitted.',
                $param->name(), $param->value()));
        }
    }

    /**
     * Get validated payload from JWS.
     *
     * @param JWS               $jws JWS
     * @param ValidationContext $ctx Validation context
     *
     * @throws ValidationException If signature validation fails
     */
    private static function _validatedPayloadFromJWS(JWS $jws,
        ValidationContext $ctx): string
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
     * @param JWS               $jws JWS
     * @param ValidationContext $ctx Validation context
     *
     * @throws ValidationException If unsecured JWT's are not allowed, or JWS
     *                             token is malformed
     */
    private static function _validatedPayloadFromUnsecuredJWS(JWS $jws,
        ValidationContext $ctx): string
    {
        if (!$ctx->isUnsecuredAllowed()) {
            throw new ValidationException('Unsecured JWS not allowed.');
        }
        if (!$jws->validate(new NoneAlgorithm())) {
            throw new ValidationException('Malformed unsecured token.');
        }
        return $jws->payload();
    }

    /**
     * Get validated payload from a signed JWS.
     *
     * @param JWS    $jws  JWS
     * @param JWKSet $keys Set of allowed keys for the signature validation
     *
     * @throws ValidationException If validation fails
     */
    private static function _validatedPayloadFromSignedJWS(JWS $jws, JWKSet $keys): string
    {
        try {
            // explicitly defined key
            if (1 === count($keys)) {
                $valid = $jws->validateWithJWK($keys->first());
            } else {
                $valid = $jws->validateWithJWKSet($keys);
            }
        } catch (\RuntimeException $e) {
            throw new ValidationException('JWS validation failed.', 0, $e);
        }
        if (!$valid) {
            throw new ValidationException('JWS signature is invalid.');
        }
        return $jws->payload();
    }

    /**
     * Get validated payload from an encrypted JWE.
     *
     * @param JWE               $jwe JWE
     * @param ValidationContext $ctx Validation context
     *
     * @throws ValidationException If decryption fails
     */
    private static function _validatedPayloadFromJWE(JWE $jwe,
        ValidationContext $ctx): string
    {
        try {
            $keys = $ctx->keys();
            // explicitly defined key
            if (1 === count($keys)) {
                return $jwe->decryptWithJWK($keys->first());
            }
            return $jwe->decryptWithJWKSet($keys);
        } catch (\RuntimeException $e) {
            throw new ValidationException('JWE validation failed.', 0, $e);
        }
    }
}
