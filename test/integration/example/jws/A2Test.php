<?php

use JWX\JWK\RSA\RSAPrivateKeyJWK;
use JWX\JWS\JWS;
use JWX\JWS\Algorithm\RS256Algorithm;
use JWX\Util\Base64;

/**
 * Test case for RFC 7515 appendix A.2.
 * Example JWS Using RSASSA-PKCS1-v1_5 SHA-256
 *
 * @group example
 *
 * @link https://tools.ietf.org/html/rfc7515#appendix-A.2
 */
class JWSUsingRS256Test extends PHPUnit_Framework_TestCase
{
    private static $_headerBytes = [123, 34, 97, 108, 103, 34, 58, 34, 82,
        83, 50, 53, 54, 34, 125];
    
    private static $_headerJSON;
    
    private static $_payloadBytes = [123, 34, 105, 115, 115, 34, 58, 34, 106,
        111, 101, 34, 44, 13, 10, 32, 34, 101, 120, 112, 34, 58, 49, 51, 48, 48,
        56, 49, 57, 51, 56, 48, 44, 13, 10, 32, 34, 104, 116, 116, 112, 58, 47,
        47, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 47, 105, 115, 95,
        114, 111, 111, 116, 34, 58, 116, 114, 117, 101, 125];
    
    private static $_payloadJSON;
    
    private static $_jwk;
    
    private static $_signatureBytes = [112, 46, 33, 137, 67, 232, 143, 209,
        30, 181, 216, 45, 191, 120, 69, 243, 65, 6, 174, 27, 129, 255, 247, 115,
        17, 22, 173, 209, 113, 125, 131, 101, 109, 66, 10, 253, 60, 150, 238, 221,
        115, 162, 102, 62, 81, 102, 104, 123, 0, 11, 135, 34, 110, 1, 135, 237,
        16, 115, 249, 69, 229, 130, 173, 252, 239, 22, 216, 90, 121, 142, 232,
        198, 109, 219, 61, 184, 151, 91, 23, 208, 148, 2, 190, 237, 213, 217, 217,
        112, 7, 16, 141, 178, 129, 96, 213, 248, 4, 12, 167, 68, 87, 98, 184, 31,
        190, 127, 249, 217, 46, 10, 231, 111, 36, 242, 91, 51, 187, 230, 244, 74,
        230, 30, 177, 4, 10, 203, 32, 4, 77, 62, 249, 18, 142, 212, 1, 48, 121,
        91, 212, 189, 59, 65, 238, 202, 208, 102, 171, 101, 25, 129, 253, 228,
        141, 247, 127, 55, 45, 195, 139, 159, 175, 221, 59, 239, 177, 139, 93,
        163, 204, 60, 46, 176, 47, 158, 58, 65, 214, 18, 202, 173, 21, 145, 18,
        115, 160, 95, 35, 185, 232, 56, 250, 175, 132, 157, 105, 132, 41, 239, 90,
        30, 136, 121, 130, 54, 195, 212, 14, 96, 69, 34, 165, 68, 200, 242, 122,
        122, 45, 184, 6, 99, 209, 108, 247, 202, 234, 86, 222, 64, 92, 178, 33,
        90, 69, 178, 194, 85, 102, 181, 90, 193, 167, 72, 160, 112, 223, 200, 163,
        42, 70, 149, 67, 208, 25, 238, 251, 71];
    
    public static function setUpBeforeClass()
    {
        self::$_headerJSON = implode("", array_map("chr", self::$_headerBytes));
        self::$_payloadJSON = implode("", array_map("chr", self::$_payloadBytes));
        self::$_jwk = RSAPrivateKeyJWK::fromJSON(
            file_get_contents(TEST_ASSETS_DIR . "/example/rfc7515-a2-jwk.json"));
    }
    
    public static function tearDownAfterClass()
    {
        self::$_headerJSON = null;
        self::$_payloadJSON = null;
        self::$_jwk = null;
    }
    
    public function testHeader()
    {
        static $expected = "eyJhbGciOiJSUzI1NiJ9";
        $header = Base64::urlEncode(self::$_headerJSON);
        $this->assertEquals($expected, $header);
        return $header;
    }
    
    public function testPayload()
    {
        static $expected_data = <<<EOF
eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt
cGxlLmNvbS9pc19yb290Ijp0cnVlfQ
EOF;
        $expected = str_replace(["\r", "\n"], "", $expected_data);
        $payload = Base64::urlEncode(self::$_payloadJSON);
        $this->assertEquals($expected, $payload);
        return $payload;
    }
    
    /**
     * @depends testHeader
     * @depends testPayload
     *
     * @param string $header
     * @param string $payload
     * @return string
     */
    public function testSign($header, $payload)
    {
        $algo = RS256Algorithm::fromPrivateKey(self::$_jwk);
        $input = "$header.$payload";
        $signature = $algo->computeSignature($input);
        $expected = implode("", array_map("chr", self::$_signatureBytes));
        $this->assertEquals($expected, $signature);
        return "$input." . Base64::urlEncode($signature);
    }
    
    /**
     * @depends testSign
     *
     * @param string $token
     */
    public function testValidate($token)
    {
        $jws = JWS::fromCompact($token);
        $algo = RS256Algorithm::fromPublicKey(self::$_jwk->publicKey());
        $this->assertTrue($jws->validate($algo));
    }
}
