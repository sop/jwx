<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWE\EncryptionAlgorithm\A128CBCHS256Algorithm;
use Sop\JWX\JWE\JWE;
use Sop\JWX\JWE\KeyAlgorithm\DirectCEKAlgorithm;
use Sop\JWX\JWK\JWK;
use Sop\JWX\JWK\JWKSet;
use Sop\JWX\JWK\Symmetric\SymmetricKeyJWK;
use Sop\JWX\JWS\Algorithm\HS256Algorithm;
use Sop\JWX\JWS\JWS;
use Sop\JWX\JWT\Claim\SubjectClaim;
use Sop\JWX\JWT\Claims;
use Sop\JWX\JWT\Exception\ValidationException;
use Sop\JWX\JWT\Header\Header;
use Sop\JWX\JWT\Header\JOSE;
use Sop\JWX\JWT\JWT;
use Sop\JWX\JWT\Parameter\ContentTypeParameter;
use Sop\JWX\JWT\Parameter\JWTParameter;
use Sop\JWX\JWT\ValidationContext;
use Sop\JWX\Util\Base64;

/**
 * @group jwt
 *
 * @internal
 */
class JWTTest extends TestCase
{
    public const KEY_128 = '123456789 123456789 123456789 12';

    public const KEY_ID = 'key-id';

    public const KEY_NESTED = '987654321 987654321 987654321 98';

    public const KEY_ID2 = 'key-id2';
    private static $_claims;

    public static function setUpBeforeClass(): void
    {
        self::$_claims = new Claims(new SubjectClaim('test'));
    }

    public static function tearDownAfterClass(): void
    {
        self::$_claims = null;
    }

    public function testCreateJWS()
    {
        $algo = new HS256Algorithm(self::KEY_128);
        $algo = $algo->withKeyID(self::KEY_ID);
        $jwt = JWT::signedFromClaims(self::$_claims, $algo);
        $this->assertInstanceOf(JWT::class, $jwt);
        return $jwt;
    }

    /**
     * @depends testCreateJWS
     */
    public function testIsJWS(JWT $jwt)
    {
        $this->assertTrue($jwt->isJWS());
    }

    /**
     * @depends testCreateJWS
     */
    public function testGetJWS(JWT $jwt)
    {
        $this->assertInstanceOf(JWS::class, $jwt->JWS());
    }

    /**
     * @depends testCreateJWS
     */
    public function testGetJWEFail(JWT $jwt)
    {
        $this->expectException(\LogicException::class);
        $jwt->JWE();
    }

    /**
     * @depends testCreateJWS
     */
    public function testHeader(JWT $jwt)
    {
        $header = $jwt->header();
        $this->assertInstanceOf(JOSE::class, $header);
    }

    /**
     * @depends testCreateJWS
     */
    public function testToken(JWT $jwt)
    {
        $this->assertIsString($jwt->token());
    }

    /**
     * @depends testCreateJWS
     */
    public function testIsUnsecured(JWT $jwt)
    {
        $this->assertFalse($jwt->isUnsecured());
    }

    /**
     * @depends testCreateJWS
     */
    public function testToString(JWT $jwt)
    {
        $token = strval($jwt);
        $this->assertIsString($token);
    }

    /**
     * @depends testCreateJWS
     */
    public function testClaimsFromJWS(JWT $jwt)
    {
        $ctx = ValidationContext::fromJWK(SymmetricKeyJWK::fromKey(self::KEY_128));
        $claims = $jwt->claims($ctx);
        $this->assertEquals(self::$_claims, $claims);
    }

    /**
     * @depends testCreateJWS
     */
    public function testClaimsFromJWSMultipleKeys(JWT $jwt)
    {
        $ctx = new ValidationContext(null, new JWKSet(
            SymmetricKeyJWK::fromKey(self::KEY_128)->withKeyID(self::KEY_ID), new JWK()));
        $claims = $jwt->claims($ctx);
        $this->assertEquals(self::$_claims, $claims);
    }

    /**
     * @depends testCreateJWS
     */
    public function testClaimsFromJWSInvalidSignature(JWT $jwt)
    {
        $parts = explode('.', $jwt->token());
        $parts[2] = '';
        $jwt = new JWT(implode('.', $parts));
        $ctx = ValidationContext::fromJWK(SymmetricKeyJWK::fromKey(self::KEY_128));
        $this->expectException(ValidationException::class);
        $jwt->claims($ctx);
    }

    /**
     * @depends testCreateJWS
     */
    public function testClaimsFromJWSFail(JWT $jwt)
    {
        $ctx = new ValidationContext(null,
            new JWKSet(SymmetricKeyJWK::fromKey(self::KEY_128), new JWK()));
        $this->expectException(ValidationException::class);
        $jwt->claims($ctx);
    }

    public function testEncryptedFromClaims()
    {
        $key_algo = new DirectCEKAlgorithm(self::KEY_128);
        $key_algo = $key_algo->withKeyID(self::KEY_ID);
        $enc_algo = new A128CBCHS256Algorithm();
        $jwt = JWT::encryptedFromClaims(self::$_claims, $key_algo, $enc_algo);
        $this->assertInstanceOf(JWT::class, $jwt);
        return $jwt;
    }

    /**
     * @depends testEncryptedFromClaims
     */
    public function testIsJWE(JWT $jwt)
    {
        $this->assertTrue($jwt->isJWE());
    }

    /**
     * @depends testEncryptedFromClaims
     */
    public function testGetJWE(JWT $jwt)
    {
        $this->assertInstanceOf(JWE::class, $jwt->JWE());
    }

    /**
     * @depends testEncryptedFromClaims
     */
    public function testGetJWSFail(JWT $jwt)
    {
        $this->expectException(\LogicException::class);
        $jwt->JWS();
    }

    /**
     * @depends testEncryptedFromClaims
     */
    public function testIsEncryptedUnsecured(JWT $jwt)
    {
        $this->assertFalse($jwt->isUnsecured());
    }

    /**
     * @depends testEncryptedFromClaims
     */
    public function testClaimsFromEncrypted(JWT $jwt)
    {
        $ctx = ValidationContext::fromJWK(
            SymmetricKeyJWK::fromKey(self::KEY_128));
        $claims = $jwt->claims($ctx);
        $this->assertEquals(self::$_claims, $claims);
    }

    /**
     * @depends testEncryptedFromClaims
     */
    public function testClaimsFromEncryptedMultipleKeys(JWT $jwt)
    {
        $ctx = new ValidationContext(null, new JWKSet(
            SymmetricKeyJWK::fromKey(self::KEY_128)->withKeyID(self::KEY_ID), new JWK()));
        $claims = $jwt->claims($ctx);
        $this->assertEquals(self::$_claims, $claims);
    }

    /**
     * @depends testEncryptedFromClaims
     */
    public function testClaimsFromEncryptedFail(JWT $jwt)
    {
        $ctx = new ValidationContext(null,
            new JWKSet(SymmetricKeyJWK::fromKey(self::KEY_128), new JWK()));
        $this->expectException(ValidationException::class);
        $jwt->claims($ctx);
    }

    public function testUnsecuredFromClaims()
    {
        $jwt = JWT::unsecuredFromClaims(self::$_claims);
        $this->assertInstanceOf(JWT::class, $jwt);
        return $jwt;
    }

    /**
     * @depends testUnsecuredFromClaims
     */
    public function testIsUnsecuredUnsecured(JWT $jwt)
    {
        $this->assertTrue($jwt->isUnsecured());
    }

    /**
     * @depends testUnsecuredFromClaims
     */
    public function testClaimsFromUnsecured(JWT $jwt)
    {
        $ctx = new ValidationContext();
        $ctx = $ctx->withUnsecuredAllowed(true);
        $claims = $jwt->claims($ctx);
        $this->assertEquals(self::$_claims, $claims);
    }

    /**
     * @depends testUnsecuredFromClaims
     */
    public function testClaimsFromUnsecuredNotAllowedFail(JWT $jwt)
    {
        $ctx = new ValidationContext();
        $this->expectException(ValidationException::class);
        $jwt->claims($ctx);
    }

    /**
     * @depends testUnsecuredFromClaims
     */
    public function testMalformedUnsecuredToken(JWT $jwt)
    {
        $parts = explode('.', $jwt->token());
        $parts[2] = Base64::urlEncode('bogus');
        $jwt = new JWT(implode('.', $parts));
        $ctx = new ValidationContext();
        $ctx = $ctx->withUnsecuredAllowed(true);
        $this->expectException(ValidationException::class);
        $jwt->claims($ctx);
    }

    public function testInvalidJWT()
    {
        $this->expectException(\UnexpectedValueException::class);
        new JWT('');
    }

    public function testProhibitedAlgorithm()
    {
        $jwt = JWT::unsecuredFromClaims(
            self::$_claims,
            new Header(new JWTParameter(JWTParameter::P_ZIP, 'dummy'))
        );
        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage('zip algorithm dummy is not permitted');
        $jwt->claims(new ValidationContext());
    }

    /**
     * @depends testCreateJWS
     */
    public function testEncryptNested(JWT $jwt)
    {
        $key_algo = new DirectCEKAlgorithm(self::KEY_NESTED);
        $key_algo = $key_algo->withKeyID(self::KEY_ID2);
        $enc_algo = new A128CBCHS256Algorithm();
        $nested = $jwt->encryptNested($key_algo, $enc_algo);
        $this->assertInstanceOf(JWT::class, $nested);
        return $nested;
    }

    /**
     * @depends testEncryptNested
     */
    public function testNestedHeader(JWT $jwt)
    {
        $cty = $jwt->header()->get(JWTParameter::P_CTY)->value();
        $this->assertEquals(ContentTypeParameter::TYPE_JWT, $cty);
    }

    /**
     * @depends testEncryptNested
     */
    public function testIsNested(JWT $jwt)
    {
        $this->assertTrue($jwt->isNested());
    }

    public function testIsNestedNoContentType()
    {
        $jwt = JWT::unsecuredFromClaims(new Claims());
        $this->assertFalse($jwt->isNested());
    }

    public function testIsNestedInvalidContentType()
    {
        $jwt = JWT::unsecuredFromClaims(new Claims(),
            new Header(new ContentTypeParameter('example')));
        $this->assertFalse($jwt->isNested());
    }

    /**
     * @depends testEncryptNested
     */
    public function testClaimsFromNested(JWT $jwt)
    {
        $keys = new JWKSet(
            SymmetricKeyJWK::fromKey(self::KEY_128)->withKeyID(self::KEY_ID),
            SymmetricKeyJWK::fromKey(self::KEY_NESTED)->withKeyID(self::KEY_ID2));
        $ctx = new ValidationContext(null, $keys);
        $claims = $jwt->claims($ctx);
        $this->assertEquals(self::$_claims, $claims);
    }

    /**
     * @depends testEncryptedFromClaims
     */
    public function testSignNested(JWT $jwt)
    {
        $nested = $jwt->signNested(new HS256Algorithm(self::KEY_128));
        $this->assertInstanceOf(JWT::class, $nested);
        return $nested;
    }
}
