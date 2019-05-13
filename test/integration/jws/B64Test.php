<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWS\Algorithm\HS256Algorithm;
use Sop\JWX\JWS\JWS;
use Sop\JWX\JWT\Header\Header;
use Sop\JWX\JWT\Parameter\B64PayloadParameter;
use Sop\JWX\JWT\Parameter\CriticalParameter;
use Sop\JWX\JWT\Parameter\JWTParameter;

/**
 * @group jws
 *
 * @internal
 */
class B64Test extends TestCase
{
    const PAYLOAD = 'PAYLOAD';

    const SECRET = 'SECRETKEY';

    /**
     * @return JWS
     */
    public function testCreate()
    {
        $jws = JWS::sign(self::PAYLOAD, new HS256Algorithm(self::SECRET),
            new Header(new B64PayloadParameter(false)));
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
        $this->assertTrue($jws->validate(new HS256Algorithm(self::SECRET)));
    }

    /**
     * @depends testCreate
     *
     * @param JWS $jws
     */
    public function testRecode(JWS $jws)
    {
        $data = $jws->toCompact();
        $result = JWS::fromCompact($data);
        $this->assertInstanceOf(JWS::class, $result);
        return $result;
    }

    /**
     * @depends testRecode
     *
     * @param JWS $jws
     */
    public function testRecodedPayload(JWS $jws)
    {
        $this->assertEquals(self::PAYLOAD, $jws->payload());
    }

    public function testCreateWithCrit()
    {
        $jws = JWS::sign(self::PAYLOAD, new HS256Algorithm(self::SECRET),
            new Header(new B64PayloadParameter(false),
                new CriticalParameter('test')));
        $crit = $jws->header()->get(JWTParameter::P_CRIT);
        $this->assertEquals(['test', 'b64'], $crit->names());
    }
}
