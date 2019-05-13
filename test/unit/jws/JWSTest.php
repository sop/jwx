<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWA\JWA;
use Sop\JWX\JWK\JWKSet;
use Sop\JWX\JWK\Parameter\KeyIDParameter as JWKID;
use Sop\JWX\JWK\Symmetric\SymmetricKeyJWK;
use Sop\JWX\JWS\Algorithm\HS256Algorithm;
use Sop\JWX\JWS\Algorithm\NoneAlgorithm;
use Sop\JWX\JWS\JWS;
use Sop\JWX\JWT\Header\Header;
use Sop\JWX\JWT\Header\JOSE;
use Sop\JWX\JWT\Parameter\B64PayloadParameter;
use Sop\JWX\JWT\Parameter\CriticalParameter;
use Sop\JWX\JWT\Parameter\JWTParameter;
use Sop\JWX\JWT\Parameter\KeyIDParameter as JWTID;

/**
 * @group jws
 *
 * @internal
 */
class JWSTest extends TestCase
{
    const KEY = '12345678';

    const KEY_ID = 'id';

    const PAYLOAD = 'PAYLOAD';

    private static $_signAlgo;

    public static function setUpBeforeClass(): void
    {
        self::$_signAlgo = new HS256Algorithm(self::KEY);
    }

    public static function tearDownAfterClass(): void
    {
        self::$_signAlgo = null;
    }

    public function testCreate()
    {
        $jws = JWS::sign(self::PAYLOAD, self::$_signAlgo,
            new Header(new JWTID(self::KEY_ID)));
        $this->assertInstanceOf(JWS::class, $jws);
        return $jws;
    }

    /**
     * @depends testCreate
     *
     * @param JWS $jws
     */
    public function testValidate(JWS $jws)
    {
        $this->assertTrue($jws->validate(self::$_signAlgo));
    }

    /**
     * @depends testCreate
     *
     * @param JWS $jws
     */
    public function testValidateInvalidAlgo(JWS $jws)
    {
        $this->expectException(\UnexpectedValueException::class);
        $jws->validate(new NoneAlgorithm());
    }

    /**
     * @depends testCreate
     *
     * @param JWS $jws
     */
    public function testValidateWithJWK(JWS $jws)
    {
        $jwk = SymmetricKeyJWK::fromKey(self::KEY);
        $this->assertTrue($jws->validateWithJWK($jwk));
    }

    /**
     * @depends testCreate
     *
     * @param JWS $jws
     */
    public function testValidateWithJWKSet(JWS $jws)
    {
        $jwk = SymmetricKeyJWK::fromKey(self::KEY)->withParameters(
            new JWKID(self::KEY_ID));
        $this->assertTrue($jws->validateWithJWKSet(new JWKSet($jwk)));
    }

    /**
     * @depends testCreate
     *
     * @param JWS $jws
     */
    public function testValidateWithJWKSetNoKeys(JWS $jws)
    {
        $this->expectException(\RuntimeException::class);
        $jws->validateWithJWKSet(new JWKSet());
    }

    /**
     * @depends testCreate
     *
     * @param JWS $jws
     */
    public function testHeader(JWS $jws)
    {
        $header = $jws->header();
        $this->assertInstanceOf(JOSE::class, $header);
        return $header;
    }

    /**
     * @depends testCreate
     *
     * @param JWS $jws
     */
    public function testAlgoName(JWS $jws)
    {
        $this->assertEquals(JWA::ALGO_HS256, $jws->algorithmName());
    }

    /**
     * @depends testCreate
     *
     * @param JWS $jws
     */
    public function testPayload(JWS $jws)
    {
        $this->assertEquals(self::PAYLOAD, $jws->payload());
    }

    /**
     * @depends testCreate
     *
     * @param JWS $jws
     */
    public function testSignature(JWS $jws)
    {
        $this->assertIsString($jws->signature());
    }

    /**
     * @depends testCreate
     *
     * @param JWS $jws
     */
    public function testToCompact(JWS $jws)
    {
        $data = $jws->toCompact();
        $this->assertIsString($data);
        return $data;
    }

    /**
     * @depends testToCompact
     *
     * @param string $data
     */
    public function testFromCompact($data)
    {
        $jws = JWS::fromCompact($data);
        $this->assertInstanceOf(JWS::class, $jws);
    }

    /**
     * @depends testCreate
     *
     * @param JWS $jws
     */
    public function testToCompactDetached(JWS $jws)
    {
        $data = $jws->toCompactDetached();
        $this->assertIsString($data);
        return $data;
    }

    /**
     * @depends testToCompactDetached
     *
     * @param string $data
     */
    public function testFromCompactDetached($data)
    {
        $jws = JWS::fromCompact($data);
        $this->assertInstanceOf(JWS::class, $jws);
    }

    public function testFromPartsFail()
    {
        $this->expectException(\UnexpectedValueException::class);
        JWS::fromParts([]);
    }

    /**
     * @depends testCreate
     *
     * @param JWS $jws
     */
    public function testToString(JWS $jws)
    {
        $data = strval($jws);
        $this->assertIsString($data);
    }

    public function testSignWithB64Param()
    {
        $header = new Header(new B64PayloadParameter(true));
        $jws = JWS::sign(self::PAYLOAD, self::$_signAlgo, $header);
        $this->assertInstanceOf(JWS::class, $jws);
        return $jws;
    }

    public function testSignWithB64ParamAsCritical()
    {
        $header = new Header(new B64PayloadParameter(true),
            new CriticalParameter(JWTParameter::P_CRIT));
        $jws = JWS::sign(self::PAYLOAD, self::$_signAlgo, $header);
        $this->assertInstanceOf(JWS::class, $jws);
    }

    /**
     * @depends testSignWithB64Param
     *
     * @param JWS $jws
     */
    public function testToCompactWithB64Param(JWS $jws)
    {
        $this->assertIsString($jws->toCompact());
    }
}
