<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWK\Symmetric\SymmetricKeyJWK;
use Sop\JWX\JWS\Algorithm\HS256Algorithm;
use Sop\JWX\JWS\JWS;
use Sop\JWX\Util\Base64;

/**
 * Test case for RFC 7515 appendix A.1.
 * Example JWS Using HMAC SHA-256.
 *
 * @group example
 *
 * @see https://tools.ietf.org/html/rfc7515#appendix-A.1
 *
 * @internal
 */
class JWSUsingHS256Test extends TestCase
{
    private static $_headerBytes = [123, 34, 116, 121, 112, 34, 58, 34, 74,
        87, 84, 34, 44, 13, 10, 32, 34, 97, 108, 103, 34, 58, 34, 72, 83, 50, 53,
        54, 34, 125, ];

    private static $_headerJSON;

    private static $_payloadBytes = [123, 34, 105, 115, 115, 34, 58, 34, 106,
        111, 101, 34, 44, 13, 10, 32, 34, 101, 120, 112, 34, 58, 49, 51, 48, 48,
        56, 49, 57, 51, 56, 48, 44, 13, 10, 32, 34, 104, 116, 116, 112, 58, 47,
        47, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 47, 105, 115, 95,
        114, 111, 111, 116, 34, 58, 116, 114, 117, 101, 125, ];

    private static $_payloadJSON;

    private static $_jwk = <<<'EOF'
{"kty":"oct",
 "k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
}
EOF;

    public static function setUpBeforeClass(): void
    {
        self::$_headerJSON = implode('', array_map('chr', self::$_headerBytes));
        self::$_payloadJSON = implode('', array_map('chr', self::$_payloadBytes));
    }

    public static function tearDownAfterClass(): void
    {
        self::$_headerJSON = null;
        self::$_payloadJSON = null;
    }

    public function testHeader()
    {
        static $expected = 'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9';
        $header = Base64::urlEncode(self::$_headerJSON);
        $this->assertEquals($expected, $header);
        return $header;
    }

    public function testPayload()
    {
        static $expected_data = <<<'EOF'
eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt
cGxlLmNvbS9pc19yb290Ijp0cnVlfQ
EOF;
        $expected = str_replace(["\r", "\n"], '', $expected_data);
        $payload = Base64::urlEncode(self::$_payloadJSON);
        $this->assertEquals($expected, $payload);
        return $payload;
    }

    public function testKey()
    {
        $jwk = SymmetricKeyJWK::fromJSON(self::$_jwk);
        $this->assertInstanceOf(SymmetricKeyJWK::class, $jwk);
        return $jwk->key();
    }

    /**
     * @depends testHeader
     * @depends testPayload
     * @depends testKey
     *
     * @param string $header
     * @param string $payload
     * @param string $key
     */
    public function testSign($header, $payload, $key)
    {
        static $expected = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
        $algo = new HS256Algorithm($key);
        $data = "{$header}.{$payload}";
        $signature = Base64::urlEncode($algo->computeSignature($data));
        $this->assertEquals($expected, $signature);
        return "{$data}.{$signature}";
    }

    /**
     * @depends testSign
     * @depends testKey
     *
     * @param string $signature
     * @param string $key
     * @param mixed  $token
     */
    public function testValidate($token, $key)
    {
        $jws = JWS::fromCompact($token);
        $this->assertTrue($jws->validate(new HS256Algorithm($key)));
    }
}
