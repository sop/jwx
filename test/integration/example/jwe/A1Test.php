<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWE\EncryptionAlgorithm\A256GCMAlgorithm;
use Sop\JWX\JWE\JWE;
use Sop\JWX\JWE\KeyAlgorithm\RSAESOAEPAlgorithm;
use Sop\JWX\JWK\RSA\RSAPrivateKeyJWK;
use Sop\JWX\Util\Base64;

/**
 * Test case for RFC 7516 appendix A.1.
 * Example JWE using RSAES-OAEP and AES GCM.
 *
 * @group example
 *
 * @see https://tools.ietf.org/html/rfc7516#appendix-A.1
 *
 * @internal
 */
class JWEUsingRSAESOAEPAndAESGCMTest extends TestCase
{
    private static $_plaintextBytes = [84, 104, 101, 32, 116, 114, 117, 101,
        32, 115, 105, 103, 110, 32, 111, 102, 32, 105, 110, 116, 101, 108, 108,
        105, 103, 101, 110, 99, 101, 32, 105, 115, 32, 110, 111, 116, 32, 107,
        110, 111, 119, 108, 101, 100, 103, 101, 32, 98, 117, 116, 32, 105, 109,
        97, 103, 105, 110, 97, 116, 105, 111, 110, 46, ];

    private static $_plaintext;

    private static $_joseJSON = '{"alg":"RSA-OAEP","enc":"A256GCM"}';

    private static $_cekBytes = [177, 161, 244, 128, 84, 143, 225, 115, 63,
        180, 3, 255, 107, 154, 212, 246, 138, 7, 110, 91, 112, 46, 34, 105, 47,
        130, 203, 46, 122, 234, 64, 252, ];

    private static $_cek;

    private static $_ivBytes = [227, 197, 117, 252, 2, 219, 233, 68, 180,
        225, 77, 219, ];

    private static $_iv;

    private static $_jwk;

    public static function setUpBeforeClass(): void
    {
        self::$_plaintext = implode('', array_map('chr', self::$_plaintextBytes));
        self::$_cek = implode('', array_map('chr', self::$_cekBytes));
        self::$_iv = implode('', array_map('chr', self::$_ivBytes));
        self::$_jwk = RSAPrivateKeyJWK::fromJSON(
            file_get_contents(TEST_ASSETS_DIR . '/example/rfc7516-a1-jwk.json'));
    }

    public static function tearDownAfterClass(): void
    {
        self::$_plaintext = null;
        self::$_cek = null;
        self::$_iv = null;
        self::$_jwk = null;
    }

    public function testEncryptKey()
    {
        $algo = RSAESOAEPAlgorithm::fromPrivateKey(self::$_jwk);
        $key = $algo->encrypt(self::$_cek);
        // encryption result cannot be asserted since RSAES is not deterministic
        $this->assertIsString($key);
        return $key;
    }

    public function testAAD()
    {
        static $expectedBytes = [101, 121, 74, 104, 98, 71, 99, 105, 79, 105,
            74, 83, 85, 48, 69, 116, 84, 48, 70, 70, 85, 67, 73, 115, 73, 109, 86,
            117, 89, 121, 73, 54, 73, 107, 69, 121, 78, 84, 90, 72, 81, 48, 48,
            105, 102, 81, ];
        $expected = implode('', array_map('chr', $expectedBytes));
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
        static $expectedCiphertextBytes = [229, 236, 166, 241, 53, 191, 115,
            196, 174, 43, 73, 109, 39, 122, 233, 96, 140, 206, 120, 52, 51, 237,
            48, 11, 190, 219, 186, 80, 111, 104, 50, 142, 47, 167, 59, 61, 181,
            127, 196, 21, 40, 82, 242, 32, 123, 143, 168, 226, 73, 216, 176, 144,
            138, 247, 106, 60, 16, 205, 160, 109, 64, 63, 192, ];
        static $expectedAuthTagBytes = [92, 80, 104, 49, 133, 25, 161, 215,
            173, 101, 219, 211, 136, 91, 210, 145, ];
        $expectedCiphertext = implode('',
            array_map('chr', $expectedCiphertextBytes));
        $expectedAuthTag = implode('', array_map('chr', $expectedAuthTagBytes));
        $algo = new A256GCMAlgorithm();
        [$ciphertext, $auth_tag] = $algo->encrypt(self::$_plaintext,
            self::$_cek, self::$_iv, $aad);
        $this->assertEquals($expectedCiphertext, $ciphertext);
        $this->assertEquals($expectedAuthTag, $auth_tag);
        return [$ciphertext, $auth_tag];
    }

    /**
     * @depends testEncrypt
     * @depends testEncryptKey
     *
     * @param mixed $data
     * @param mixed $enc_key
     */
    public function testDecrypt($data, $enc_key)
    {
        $header = Base64::urlEncode(self::$_joseJSON);
        $enc_key_b64 = Base64::urlEncode($enc_key);
        $iv = Base64::urlEncode(self::$_iv);
        $ciphertext = Base64::urlEncode($data[0]);
        $tag = Base64::urlEncode($data[1]);
        $token = "{$header}.{$enc_key_b64}.{$iv}.{$ciphertext}.{$tag}";
        $jwe = JWE::fromCompact($token);
        $key_algo = RSAESOAEPAlgorithm::fromPrivateKey(self::$_jwk);
        $enc_algo = new A256GCMAlgorithm();
        $plaintext = $jwe->decrypt($key_algo, $enc_algo);
        $this->assertEquals(self::$_plaintext, $plaintext);
    }
}
