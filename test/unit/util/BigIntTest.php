<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\Util\BigInt;

/**
 * @group util
 * @group bigint
 *
 * @internal
 */
class BigIntTest extends TestCase
{
    public const BASE_10 = '255';

    public function testCreate()
    {
        $bi = BigInt::fromBase10(self::BASE_10);
        $this->assertInstanceOf(BigInt::class, $bi);
        return $bi;
    }

    /**
     * @depends testCreate
     */
    public function testBase10(BigInt $bi)
    {
        $this->assertEquals(self::BASE_10, $bi->base10());
    }

    /**
     * @depends testCreate
     */
    public function testBase16(BigInt $bi)
    {
        $this->assertEquals('ff', $bi->base16());
    }

    /**
     * @depends testCreate
     */
    public function testBase256(BigInt $bi)
    {
        $this->assertEquals("\xff", $bi->base256());
    }

    /**
     * @depends testCreate
     */
    public function testToString(BigInt $bi)
    {
        $str = strval($bi);
        $this->assertEquals(self::BASE_10, $str);
    }

    public function testFromBase256()
    {
        $bi = BigInt::fromBase256("\xff");
        $this->assertEquals('255', $bi);
    }
}
