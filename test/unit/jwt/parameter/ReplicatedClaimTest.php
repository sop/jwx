<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWT\Claim\RegisteredClaim;
use Sop\JWX\JWT\Claim\SubjectClaim;
use Sop\JWX\JWT\Parameter\JWTParameter;
use Sop\JWX\JWT\Parameter\ReplicatedClaimParameter;

/**
 * @group jwt
 * @group parameter
 *
 * @internal
 */
class ReplicatedClaimParameterTest extends TestCase
{
    public function testCreate()
    {
        $param = new ReplicatedClaimParameter(new SubjectClaim('test'));
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
