<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWK\RSA\RSAPrivateKeyJWK;
use Sop\JWX\JWS\Algorithm\RSASSAPKCS1Algorithm;
use Sop\JWX\JWS\JWS;
use Sop\JWX\JWT\Header\Header;
use Sop\JWX\Util\Base64;

/**
 * @internal
 */
class CookbookRSAv15SignatureTest extends TestCase
{
    private static $_testData;

    public static function setUpBeforeClass(): void
    {
        $json = file_get_contents(COOKBOOK_DIR . '/jws/4_1.rsa_v15_signature.json');
        self::$_testData = json_decode($json, true);
    }

    public static function tearDownAfterClass(): void
    {
        self::$_testData = null;
    }

    public function testPrivateKey()
    {
        $jwk = RSAPrivateKeyJWK::fromArray(self::$_testData['input']['key']);
        $this->assertInstanceOf(RSAPrivateKeyJWK::class, $jwk);
        return $jwk;
    }

    public function testHeader()
    {
        $header = Header::fromArray(self::$_testData['signing']['protected']);
        $encoded = Base64::urlEncode($header->toJSON());
        $this->assertEquals(self::$_testData['signing']['protected_b64u'],
            $encoded);
        return $header;
    }

    /**
     * @depends testPrivateKey
     * @depends testHeader
     */
    public function testSign(RSAPrivateKeyJWK $jwk, Header $header)
    {
        $payload = self::$_testData['input']['payload'];
        $algo = RSASSAPKCS1Algorithm::fromJWK($jwk, $header);
        $jws = JWS::sign($payload, $algo, $header);
        $this->assertEquals(self::$_testData['signing']['sig'],
            Base64::urlEncode($jws->signature()));
        return $jws;
    }

    /**
     * @depends testSign
     */
    public function testCompact(JWS $jws)
    {
        $this->assertEquals(self::$_testData['output']['compact'],
            $jws->toCompact());
    }
}
