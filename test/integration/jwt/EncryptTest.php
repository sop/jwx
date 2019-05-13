<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWE\EncryptionAlgorithm\A128CBCHS256Algorithm;
use Sop\JWX\JWE\KeyAlgorithm\PBES2HS256A128KWAlgorithm;
use Sop\JWX\JWT\Claim\IssuedAtClaim;
use Sop\JWX\JWT\Claims;
use Sop\JWX\JWT\JWT;

/**
 * @group jwt
 * @group jwe
 *
 * @internal
 */
class JWTEncryptTest extends TestCase
{
    private static $_claims;

    private static $_keyAlgo;

    private static $_encAlgo;

    public static function setUpBeforeClass(): void
    {
        self::$_claims = new Claims(IssuedAtClaim::now());
        self::$_keyAlgo = PBES2HS256A128KWAlgorithm::fromPassword('p4s5W0rD');
        self::$_encAlgo = new A128CBCHS256Algorithm();
    }

    public static function tearDownAfterClass(): void
    {
        self::$_claims = null;
        self::$_keyAlgo = null;
        self::$_encAlgo = null;
    }

    public function testCreate()
    {
        $jwt = JWT::encryptedFromClaims(self::$_claims, self::$_keyAlgo,
            self::$_encAlgo);
        $this->assertInstanceOf(JWT::class, $jwt);
        return $jwt;
    }
}
