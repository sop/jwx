<?php

use JWX\JWE\JWE;
use JWX\JWE\EncryptionAlgorithm\A128CBCHS256Algorithm;
use JWX\JWE\KeyAlgorithm\RSAESPKCS1Algorithm;
use JWX\JWK\RSA\RSAPrivateKeyJWK;
use JWX\Util\Base64;

/**
 * Test case for RFC 7516 appendix A.2.
 * Example JWE using RSAES-PKCS1-v1_5 and AES_128_CBC_HMAC_SHA_256
 *
 * @group example
 *
 * @link https://tools.ietf.org/html/rfc7516#appendix-A.2
 */
class JWEUsingRSAES15AndAESCBCTest extends PHPUnit_Framework_TestCase
{
    private static $_plaintextBytes = [76, 105, 118, 101, 32, 108, 111, 110,
        103, 32, 97, 110, 100, 32, 112, 114, 111, 115, 112, 101, 114, 46];
    
    private static $_plaintext;
    
    private static $_joseJSON = '{"alg":"RSA1_5","enc":"A128CBC-HS256"}';
    
    private static $_cekBytes = [4, 211, 31, 197, 84, 157, 252, 254, 11, 100,
        157, 250, 63, 170, 106, 206, 107, 124, 212, 45, 111, 107, 9, 219, 200,
        177, 0, 240, 143, 156, 44, 207];
    
    private static $_cek;
    
    private static $_ivBytes = [3, 22, 60, 12, 43, 67, 104, 105, 108, 108,
        105, 99, 111, 116, 104, 101];
    
    private static $_iv;
    
    private static $_jwk;
    
    public static function setUpBeforeClass()
    {
        self::$_plaintext = implode("", array_map("chr", self::$_plaintextBytes));
        self::$_cek = implode("", array_map("chr", self::$_cekBytes));
        self::$_iv = implode("", array_map("chr", self::$_ivBytes));
        self::$_jwk = RSAPrivateKeyJWK::fromJSON(
            file_get_contents(TEST_ASSETS_DIR . "/example/rfc7516-a2-jwk.json"));
    }
    
    public static function tearDownAfterClass()
    {
        self::$_plaintext = null;
        self::$_cek = null;
        self::$_iv = null;
        self::$_jwk = null;
    }
    
    public function testEncryptKey()
    {
        $algo = RSAESPKCS1Algorithm::fromPrivateKey(self::$_jwk);
        $key = $algo->encrypt(self::$_cek);
        // encryption result cannot be asserted since RSAES is not deterministic
        $this->assertInternalType("string", $key);
        return $key;
    }
    
    public function testAAD()
    {
        static $expectedBytes = [101, 121, 74, 104, 98, 71, 99, 105, 79, 105,
            74, 83, 85, 48, 69, 120, 88, 122, 85, 105, 76, 67, 74, 108, 98, 109,
            77, 105, 79, 105, 74, 66, 77, 84, 73, 52, 81, 48, 74, 68, 76, 85, 104,
            84, 77, 106, 85, 50, 73, 110, 48];
        $expected = implode("", array_map("chr", $expectedBytes));
        $aad = Base64::urlEncode(self::$_joseJSON);
        $this->assertEquals($expected, $aad);
        return $aad;
    }
    
    /**
     * @depends testAAD
     *
     * @param string $aad
     */
    public function testEncrypt($aad)
    {
        static $expectedCiphertextBytes = [40, 57, 83, 181, 119, 33, 133,
            148, 198, 185, 243, 24, 152, 230, 6, 75, 129, 223, 127, 19, 210, 82,
            183, 230, 168, 33, 215, 104, 143, 112, 56, 102];
        static $expectedAuthTagBytes = [246, 17, 244, 190, 4, 95, 98, 3, 231,
            0, 115, 157, 242, 203, 100, 191];
        $expectedCiphertext = implode("",
            array_map("chr", $expectedCiphertextBytes));
        $expectedAuthTag = implode("", array_map("chr", $expectedAuthTagBytes));
        $algo = new A128CBCHS256Algorithm();
        list($ciphertext, $auth_tag) = $algo->encrypt(self::$_plaintext,
            self::$_cek, self::$_iv, $aad);
        $this->assertEquals($expectedCiphertext, $ciphertext);
        $this->assertEquals($expectedAuthTag, $auth_tag);
        return [$ciphertext, $auth_tag];
    }
    
    /**
     * @depends testEncrypt
     * @depends testEncryptKey
     */
    public function testDecrypt($data, $enc_key)
    {
        $header = Base64::urlEncode(self::$_joseJSON);
        $enc_key_b64 = Base64::urlEncode($enc_key);
        $iv = Base64::urlEncode(self::$_iv);
        $ciphertext = Base64::urlEncode($data[0]);
        $tag = Base64::urlEncode($data[1]);
        $token = "$header.$enc_key_b64.$iv.$ciphertext.$tag";
        $jwe = JWE::fromCompact($token);
        $key_algo = RSAESPKCS1Algorithm::fromPrivateKey(self::$_jwk);
        $enc_algo = new A128CBCHS256Algorithm();
        $plaintext = $jwe->decrypt($key_algo, $enc_algo);
        $this->assertEquals(self::$_plaintext, $plaintext);
    }
}
