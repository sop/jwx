<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWS\Algorithm\HS256Algorithm;
use Sop\JWX\JWT\Claim\IssuedAtClaim;
use Sop\JWX\JWT\Claims;
use Sop\JWX\JWT\JWT;

/**
 * @group jwt
 * @group jws
 *
 * @internal
 */
class JWTSigningTest extends TestCase
{
    private static $_claims;

    private static $_signatureAlgo;

    public static function setUpBeforeClass(): void
    {
        self::$_claims = new Claims(IssuedAtClaim::now());
        self::$_signatureAlgo = new HS256Algorithm('secret');
    }

    public static function tearDownAfterClass(): void
    {
        self::$_claims = null;
        self::$_signatureAlgo = null;
    }

    public function testCreate()
    {
        $jwt = JWT::signedFromClaims(self::$_claims, self::$_signatureAlgo);
        $this->assertInstanceOf(JWT::class, $jwt);
        return $jwt;
    }
}
