<?php

use JWX\JWT\Claim\RegisteredClaim;
use JWX\JWT\Claim\SubjectClaim;
use JWX\JWT\Parameter\JWTParameter;
use JWX\JWT\Parameter\ReplicatedClaimParameter;
use PHPUnit\Framework\TestCase;

/**
 * @group jwt
 * @group parameter
 */
class ReplicatedClaimParameterTest extends TestCase
{
    public function testCreate()
    {
        $param = new ReplicatedClaimParameter(new SubjectClaim("test"));
        $this->assertInstanceOf(ReplicatedClaimParameter::class, $param);
        return $param;
    }
    
    /**
     * @depends testCreate
     *
     * @param JWTParameter $param
     */
    public function testParamName(JWTParameter $param)
    {
        $this->assertEquals(RegisteredClaim::NAME_SUBJECT, $param->name());
    }
}
