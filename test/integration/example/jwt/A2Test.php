<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWE\EncryptionAlgorithm\A128CBCHS256Algorithm;
use Sop\JWX\JWE\JWE;
use Sop\JWX\JWE\KeyAlgorithm\RSAESPKCS1Algorithm;
use Sop\JWX\JWK\RSA\RSAPrivateKeyJWK;
use Sop\JWX\JWT\Header\Header;
use Sop\JWX\Util\Base64;

/**
 * Test case for RFC 7519 appendix A.2.
 * Example Nested JWT.
 *
 * @group example
 *
 * @see https://tools.ietf.org/html/rfc7519#appendix-A.2
 *
 * @internal
 */
class NestedJWTTest extends TestCase
{
    private static $_innerJWTSrc = <<<'EOF'
eyJhbGciOiJSUzI1NiJ9
.
eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt
cGxlLmNvbS9pc19yb290Ijp0cnVlfQ
.
cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7
AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4
BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K
0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqv
hJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrB
p0igcN_IoypGlUPQGe77Rw
EOF;

    private static $_innerJWT;

    private static $_joseJSON = '{"alg":"RSA1_5","enc":"A128CBC-HS256","cty":"JWT"}';

    private static $_ivBytes = [82, 101, 100, 109, 111, 110, 100, 32, 87, 65,
        32, 57, 56, 48, 53, 50, ];

    private static $_iv;

    private static $_cekBase64 = 'GawgguFyGrWKav7AX4VKUg';

    private static $_cek;

    /**
     * Example gives CEK as a base64 encoded string "GawgguFyGrWKav7AX4VKUg",
     * which decodes to 16 bytes long key.
     * A128CBC-HS256 requires a key of 32 bytes, so i'm not sure how to
     * deal with this.
     * Here's an encrypted CEK from the final result.
     */
    private static $_encryptedCEKBase64 = <<<'EOF'
g_hEwksO1Ax8Qn7HoN-BVeBoa8FXe0kpyk_XdcSmxvcM5_P296JXXtoHISr_DD_M
qewaQSH4dZOQHoUgKLeFly-9RI11TG-_Ge1bZFazBPwKC5lJ6OLANLMd0QSL4fYE
b9ERe-epKYE3xb2jfY1AltHqBO-PM6j23Guj2yDKnFv6WO72tteVzm_2n17SBFvh
DuR9a2nHTE67pe0XGBUS_TK7ecA-iVq5COeVdJR4U4VZGGlxRGPLRHvolVLEHx6D
YyLpw30Ay9R6d68YCLi9FYTq3hIXPK_-dmPlOUlKvPr1GgJzRoeC9G5qCvdcHWsq
JGTO_z3Wfo5zsqwkxruxwA
EOF;

    private static $_encryptedCEK;

    private static $_jwk;

    public static function setUpBeforeClass(): void
    {
        self::$_innerJWT = str_replace(["\r", "\n"], '', self::$_innerJWTSrc);
        self::$_iv = implode('', array_map('chr', self::$_ivBytes));
        self::$_cek = Base64::urlDecode(self::$_cekBase64);
        self::$_encryptedCEK = Base64::urlDecode(
            str_replace(["\r", "\n"], '', self::$_encryptedCEKBase64));
        self::$_jwk = RSAPrivateKeyJWK::fromJSON(
            file_get_contents(TEST_ASSETS_DIR . '/example/rfc7516-a2-jwk.json'));
    }

    public static function tearDownAfterClass(): void
    {
        self::$_innerJWT = null;
        self::$_iv = null;
        self::$_cek = null;
        self::$_encryptedCEK = null;
        self::$_jwk = null;
    }

    public function testHeader()
    {
        static $expected = 'eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiY3R5IjoiSldUIn0';
        $header = Header::fromJSON(self::$_joseJSON);
        $this->assertEquals($expected, Base64::urlEncode($header->toJSON()));
        return $header;
    }

    public function testDecryptCEK()
    {
        $algo = RSAESPKCS1Algorithm::fromPrivateKey(self::$_jwk);
        $key = $algo->decrypt(self::$_encryptedCEK);
        $this->assertEquals(32, strlen($key));
        return $key;
    }

    /**
     * @depends testDecryptCEK
     *
     * @param mixed $cek
     */
    public function testEncrypt($cek)
    {
        static $expectedCiphertextBase64 = <<<'EOF'
VwHERHPvCNcHHpTjkoigx3_ExK0Qc71RMEParpatm0X_qpg-w8kozSjfNIPPXiTB
BLXR65CIPkFqz4l1Ae9w_uowKiwyi9acgVztAi-pSL8GQSXnaamh9kX1mdh3M_TT
-FZGQFQsFhu0Z72gJKGdfGE-OE7hS1zuBD5oEUfk0Dmb0VzWEzpxxiSSBbBAzP10
l56pPfAtrjEYw-7ygeMkwBl6Z_mLS6w6xUgKlvW6ULmkV-uLC4FUiyKECK4e3WZY
Kw1bpgIqGYsw2v_grHjszJZ-_I5uM-9RA8ycX9KqPRp9gc6pXmoU_-27ATs9XCvr
ZXUtK2902AUzqpeEUJYjWWxSNsS-r1TJ1I-FMJ4XyAiGrfmo9hQPcNBYxPz3GQb2
8Y5CLSQfNgKSGt0A4isp1hBUXBHAndgtcslt7ZoQJaKe_nNJgNliWtWpJ_ebuOpE
l8jdhehdccnRMIwAmU1n7SPkmhIl1HlSOpvcvDfhUN5wuqU955vOBvfkBOh5A11U
zBuo2WlgZ6hYi9-e3w29bR0C2-pp3jbqxEDw3iWaf2dc5b-LnR0FEYXvI_tYk5rd
_J9N0mg0tQ6RbpxNEMNoA9QWk5lgdPvbh9BaO195abQ
EOF;
        static $expectedAuthTagBase64 = 'AVO9iT5AV4CzvDJCdhSFlQ';
        $expectedCiphertext = Base64::urlDecode(
            str_replace(["\r", "\n"], '', $expectedCiphertextBase64));
        $expectedAuthTag = Base64::urlDecode($expectedAuthTagBase64);
        $aad = Base64::urlEncode(self::$_joseJSON);
        $algo = new A128CBCHS256Algorithm();
        [$ciphertext, $auth_tag] = $algo->encrypt(self::$_innerJWT, $cek, self::$_iv, $aad);
        $this->assertEquals($expectedCiphertext, $ciphertext);
        $this->assertEquals($expectedAuthTag, $auth_tag);
        return [$ciphertext, $auth_tag];
    }

    /**
     * @depends testEncrypt
     * @depends testDecryptCEK
     *
     * @param string $data
     * @param string $cek
     */
    public function testDecrypt($data, $cek)
    {
        $header = Base64::urlEncode(self::$_joseJSON);
        $key = Base64::urlEncode(self::$_encryptedCEK);
        $iv = Base64::urlEncode(self::$_iv);
        $ciphertext = Base64::urlEncode($data[0]);
        $tag = Base64::urlEncode($data[1]);
        $token = "{$header}.{$key}.{$iv}.{$ciphertext}.{$tag}";
        $jwe = JWE::fromCompact($token);
        $key_algo = RSAESPKCS1Algorithm::fromPrivateKey(self::$_jwk);
        $enc_algo = new A128CBCHS256Algorithm();
        $plaintext = $jwe->decrypt($key_algo, $enc_algo);
        $this->assertEquals(self::$_innerJWT, $plaintext);
    }
}
