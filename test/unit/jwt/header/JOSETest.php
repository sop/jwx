<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWA\JWA;
use Sop\JWX\JWT\Header\Header;
use Sop\JWX\JWT\Header\JOSE;
use Sop\JWX\JWT\Parameter\ContentTypeParameter;
use Sop\JWX\JWT\Parameter\JWTParameter;
use Sop\JWX\JWT\Parameter\TypeParameter;

/**
 * @group jwt
 * @group header
 *
 * @internal
 */
class JOSETest extends TestCase
{
    public function testCreate()
    {
        $jose = new JOSE(new Header(new TypeParameter('test')));
        $this->assertInstanceOf(JOSE::class, $jose);
        return $jose;
    }

    /**
     * @depends testCreate
     *
     * @param JOSE $jose
     */
    public function testHas(JOSE $jose)
    {
        $this->assertTrue($jose->has(JWTParameter::PARAM_TYPE));
    }

    /**
     * @depends testCreate
     *
     * @param JOSE $jose
     */
    public function testMerge(JOSE $jose)
    {
        $jose = $jose->withHeader(new Header(new ContentTypeParameter('test')));
        $this->assertInstanceOf(JOSE::class, $jose);
        return $jose;
    }

    /**
     * @depends testMerge
     *
     * @param JOSE $jose
     */
    public function testMergedCount(JOSE $jose)
    {
        $this->assertCount(2, $jose);
    }

    /**
     * @depends testCreate
     *
     * @param JOSE $jose
     */
    public function testDuplicateFail(JOSE $jose)
    {
        $this->expectException(\RuntimeException::class);
        $jose->withHeader(new Header(new TypeParameter('dup')));
    }

    public function testIsJWS()
    {
        $jose = new JOSE(Header::fromArray(['alg' => JWA::ALGO_HS256]));
        $this->assertTrue($jose->isJWS());
        $this->assertFalse($jose->isJWE());
    }

    public function testIsJWE()
    {
        $jose = new JOSE(Header::fromArray(['enc' => JWA::ALGO_A128CBC_HS256]));
        $this->assertTrue($jose->isJWE());
        $this->assertFalse($jose->isJWS());
    }
}
