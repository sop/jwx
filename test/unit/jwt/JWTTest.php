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
    const KEY_128 = '123456789 123456789 123456789 12';

    const KEY_ID = 'key-id';

    const KEY_NESTED = '987654321 987654321 987654321 98';

    const KEY_ID2 = 'key-id2';
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
     *
     * @param JWT $jwt
     */
    public function testIsJWS(JWT $jwt)
    {
        $this->assertTrue($jwt->isJWS());
    }

    /**
     * @depends testCreateJWS
     *
     * @param JWT $jwt
     */
    public function testGetJWS(JWT $jwt)
    {
        $this->assertInstanceOf(JWS::class, $jwt->JWS());
    }

    /**
     * @depends testCreateJWS
     *
     * @param JWT $jwt
     */
    public function testGetJWEFail(JWT $jwt)
    {
        $this->expectException(\LogicException::class);
        $jwt->JWE();
    }

    /**
     * @depends testCreateJWS
     *
     * @param JWT $jwt
     */
    public function testHeader(JWT $jwt)
    {
        $header = $jwt->header();
        $this->assertInstanceOf(JOSE::class, $header);
    }

    /**
     * @depends testCreateJWS
     *
     * @param JWT $jwt
     */
    public function testToken(JWT $jwt)
    {
        $this->assertIsString($jwt->token());
    }

    /**
     * @depends testCreateJWS
     *
     * @param JWT $jwt
     */
    public function testIsUnsecured(JWT $jwt)
    {
        $this->assertFalse($jwt->isUnsecured());
    }

    /**
     * @depends testCreateJWS
     *
     * @param JWT $jwt
     */
    public function testToString(JWT $jwt)
    {
        $token = strval($jwt);
        $this->assertIsString($token);
    }

    /**
     * @depends testCreateJWS
     *
     * @param JWT $jwt
     */
    public function testClaimsFromJWS(JWT $jwt)
    {
        $ctx = ValidationContext::fromJWK(SymmetricKeyJWK::fromKey(self::KEY_128));
        $claims = $jwt->claims($ctx);
        $this->assertEquals(self::$_claims, $claims);
    }

    /**
     * @depends testCreateJWS
     *
     * @param JWT $jwt
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
     *
     * @param JWT $jwt
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
     *
     * @param JWT $jwt
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
     *
     * @param JWT $jwt
     */
    public function testIsJWE(JWT $jwt)
    {
        $this->assertTrue($jwt->isJWE());
    }

    /**
     * @depends testEncryptedFromClaims
     *
     * @param JWT $jwt
     */
    public function testGetJWE(JWT $jwt)
    {
        $this->assertInstanceOf(JWE::class, $jwt->JWE());
    }

    /**
     * @depends testEncryptedFromClaims
     *
     * @param JWT $jwt
     */
    public function testGetJWSFail(JWT $jwt)
    {
        $this->expectException(\LogicException::class);
        $jwt->JWS();
    }

    /**
     * @depends testEncryptedFromClaims
     *
     * @param JWT $jwt
     */
    public function testIsEncryptedUnsecured(JWT $jwt)
    {
        $this->assertFalse($jwt->isUnsecured());
    }

    /**
     * @depends testEncryptedFromClaims
     *
     * @param JWT $jwt
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
     *
     * @param JWT $jwt
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
     *
     * @param JWT $jwt
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
     *
     * @param JWT $jwt
     */
    public function testIsUnsecuredUnsecured(JWT $jwt)
    {
        $this->assertTrue($jwt->isUnsecured());
    }

    /**
     * @depends testUnsecuredFromClaims
     *
     * @param JWT $jwt
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
     *
     * @param JWT $jwt
     */
    public function testClaimsFromUnsecuredNotAllowedFail(JWT $jwt)
    {
        $ctx = new ValidationContext();
        $this->expectException(ValidationException::class);
        $jwt->claims($ctx);
    }

    /**
     * @depends testUnsecuredFromClaims
     *
     * @param JWT $jwt
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

    /**
     * @depends testCreateJWS
     *
     * @param JWT $jwt
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
     *
     * @param JWT $jwt
     */
    public function testNestedHeader(JWT $jwt)
    {
        $cty = $jwt->header()->get(JWTParameter::P_CTY)->value();
        $this->assertEquals(ContentTypeParameter::TYPE_JWT, $cty);
    }

    /**
     * @depends testEncryptNested
     *
     * @param JWT $jwt
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
     *
     * @param JWT $jwt
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
     *
     * @param JWT $jwt
     */
    public function testSignNested(JWT $jwt)
    {
        $nested = $jwt->signNested(new HS256Algorithm(self::KEY_128));
        $this->assertInstanceOf(JWT::class, $nested);
        return $nested;
    }
}
