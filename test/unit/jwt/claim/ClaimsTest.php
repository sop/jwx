<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWT\Claim\AudienceClaim;
use Sop\JWX\JWT\Claim\Claim;
use Sop\JWX\JWT\Claim\IssuerClaim;
use Sop\JWX\JWT\Claim\RegisteredClaim;
use Sop\JWX\JWT\Claim\SubjectClaim;
use Sop\JWX\JWT\Claims;
use Sop\JWX\JWT\ValidationContext;

/**
 * @group jwt
 * @group claim
 *
 * @internal
 */
class ClaimsTest extends TestCase
{
    public function testCreate()
    {
        $claims = new Claims(new IssuerClaim('issuer'),
            new SubjectClaim('subject'), new AudienceClaim('test'));
        $this->assertInstanceOf(Claims::class, $claims);
        return $claims;
    }

    /**
     * @depends testCreate
     *
     * @return string
     */
    public function testToJSON(Claims $claims)
    {
        $json = $claims->toJSON();
        $this->assertJson($json);
        return $json;
    }

    /**
     * @depends testToJSON
     *
     * @param string $json
     */
    public function testFromJSON($json)
    {
        $claims = Claims::fromJSON($json);
        $this->assertInstanceOf(Claims::class, $claims);
        return $claims;
    }

    public function testFromJSONFail()
    {
        $this->expectException(\UnexpectedValueException::class);
        Claims::fromJSON('null');
    }

    /**
     * @depends testCreate
     * @depends testFromJSON
     */
    public function testRecoded(Claims $ref, Claims $claims)
    {
        $this->assertEquals($ref, $claims);
    }

    /**
     * @depends testCreate
     *
     * @return string
     */
    public function testHas(Claims $claims)
    {
        $this->assertTrue($claims->has(RegisteredClaim::NAME_ISSUER));
    }

    /**
     * @depends testCreate
     *
     * @return string
     */
    public function testGet(Claims $claims)
    {
        $this->assertInstanceOf(Claim::class,
            $claims->get(RegisteredClaim::NAME_ISSUER));
    }

    /**
     * @depends testCreate
     *
     * @return string
     */
    public function testGetFails(Claims $claims)
    {
        $this->expectException(\LogicException::class);
        $claims->get('nope');
    }

    /**
     * @depends testCreate
     *
     * @return string
     */
    public function testGetClaims(Claims $claims)
    {
        $this->assertContainsOnlyInstancesOf(Claim::class, $claims->all());
    }

    /**
     * @depends testCreate
     *
     * @return string
     */
    public function testCount(Claims $claims)
    {
        $this->assertCount(3, $claims);
    }

    /**
     * @depends testCreate
     *
     * @return string
     */
    public function testIterator(Claims $claims)
    {
        $values = [];
        foreach ($claims as $claim) {
            $values[] = $claim;
        }
        $this->assertContainsOnlyInstancesOf(Claim::class, $values);
    }

    /**
     * @depends testCreate
     *
     * @return string
     */
    public function testWithClaims(Claims $claims)
    {
        $claims = $claims->withClaims(new Claim('name', 'value'));
        $this->assertCount(4, $claims);
    }

    /**
     * @depends testCreate
     *
     * @return string
     */
    public function testToString(Claims $claims)
    {
        $str = strval($claims);
        $this->assertJson($str);
    }

    /**
     * @depends testCreate
     */
    public function testIsValid(Claims $claims)
    {
        $ctx = new ValidationContext(['iss' => 'issuer']);
        $this->assertTrue($claims->isValid($ctx));
    }

    /**
     * @depends testCreate
     */
    public function testIsNotValid(Claims $claims)
    {
        $ctx = new ValidationContext(['iss' => 'fail']);
        $this->assertFalse($claims->isValid($ctx));
    }
}
