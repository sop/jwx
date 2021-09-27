<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWK\Symmetric\SymmetricKeyJWK;
use Sop\JWX\JWS\Algorithm\HMACAlgorithm;
use Sop\JWX\JWS\JWS;
use Sop\JWX\JWT\Header\Header;
use Sop\JWX\Util\Base64;

/**
 * @internal
 */
class CookbookSignatureWithDetachedContentTest extends TestCase
{
    private static $_testData;

    public static function setUpBeforeClass(): void
    {
        $json = file_get_contents(COOKBOOK_DIR . '/jws/4_5.signature_with_detached_content.json');
        self::$_testData = json_decode($json, true);
    }

    public static function tearDownAfterClass(): void
    {
        self::$_testData = null;
    }

    public function testSymmetricKey()
    {
        $jwk = SymmetricKeyJWK::fromArray(self::$_testData['input']['key']);
        $this->assertInstanceOf(SymmetricKeyJWK::class, $jwk);
        return $jwk;
    }

    public function testHeader()
    {
        $header = Header::fromArray(self::$_testData['signing']['protected']);
        $encoded = Base64::urlEncode($header->toJSON());
        $this->assertEquals(self::$_testData['signing']['protected_b64u'], $encoded);
        return $header;
    }

    /**
     * @depends testSymmetricKey
     * @depends testHeader
     */
    public function testSign(SymmetricKeyJWK $jwk, Header $header)
    {
        $payload = self::$_testData['input']['payload'];
        $algo = HMACAlgorithm::fromJWK($jwk, $header);
        $jws = JWS::sign($payload, $algo, $header);
        $this->assertEquals(self::$_testData['signing']['sig'],
            Base64::urlEncode($jws->signature()));
        return $jws;
    }

    /**
     * @depends testSign
     */
    public function testCompactDetached(JWS $jws)
    {
        $this->assertEquals(self::$_testData['output']['compact'],
            $jws->toCompactDetached());
    }
}
