<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWE\CompressionAlgorithm\CompressionFactory;
use Sop\JWX\JWE\EncryptionAlgorithm\EncryptionAlgorithmFactory;
use Sop\JWX\JWE\JWE;
use Sop\JWX\JWE\KeyAlgorithm\AESKWAlgorithm;
use Sop\JWX\JWK\Symmetric\SymmetricKeyJWK;
use Sop\JWX\JWT\Header\Header;
use Sop\JWX\Util\Base64;

/**
 * @internal
 */
class CookbookCompressedContentTest extends TestCase
{
    private static $_testData;

    public static function setUpBeforeClass(): void
    {
        $json = file_get_contents(
            COOKBOOK_DIR . '/jwe/5_9.compressed_content.json');
        self::$_testData = json_decode($json, true);
    }

    public static function tearDownAfterClass(): void
    {
        self::$_testData = null;
    }

    public function testCreateJWK()
    {
        $jwk = SymmetricKeyJWK::fromArray(self::$_testData['input']['key']);
        $this->assertInstanceOf(SymmetricKeyJWK::class, $jwk);
        return $jwk;
    }

    /**
     * @depends testCreateJWK
     */
    public function testEncryptKey(SymmetricKeyJWK $jwk)
    {
        $algo = AESKWAlgorithm::fromJWK($jwk, new Header());
        $cek = Base64::urlDecode(self::$_testData['generated']['cek']);
        $enc_key = $algo->encrypt($cek);
        $this->assertEquals(self::$_testData['encrypting_key']['encrypted_key'],
            Base64::urlEncode($enc_key));
    }

    public function testCompressedContent()
    {
        $algo = CompressionFactory::algoByName(self::$_testData['input']['zip']);
        $content = $algo->compress(self::$_testData['input']['plaintext']);
        $this->assertEquals(self::$_testData['generated']['plaintext_c'],
            Base64::urlEncode($content));
        return $content;
    }

    public function testHeader()
    {
        $header = Header::fromArray(
            self::$_testData['encrypting_content']['protected']);
        $encoded = Base64::urlEncode($header->toJSON());
        $this->assertEquals(
            self::$_testData['encrypting_content']['protected_b64u'], $encoded);
        return $header;
    }

    /**
     * @depends testCreateJWK
     * @depends testCompressedContent
     * @depends testHeader
     *
     * @param mixed $content
     */
    public function testContentEncryption(SymmetricKeyJWK $jwk, $content,
        Header $header)
    {
        $iv = Base64::urlDecode(self::$_testData['generated']['iv']);
        $aad = Base64::urlEncode($header->toJSON());
        $cek = AESKWAlgorithm::fromJWK($jwk, $header)->decrypt(
            Base64::urlDecode(
                self::$_testData['encrypting_key']['encrypted_key']));
        $algo = EncryptionAlgorithmFactory::algoByName(
            self::$_testData['input']['enc']);
        [$ciphertext, $auth_tag] = $algo->encrypt($content, $cek, $iv, $aad);
        $this->assertEquals(
            self::$_testData['encrypting_content']['ciphertext'],
            Base64::urlEncode($ciphertext));
        $this->assertEquals(self::$_testData['encrypting_content']['tag'],
            Base64::urlEncode($auth_tag));
    }

    /**
     * @depends testCreateJWK
     * @depends testHeader
     */
    public function testCreateJWE(SymmetricKeyJWK $jwk, Header $header)
    {
        $payload = self::$_testData['input']['plaintext'];
        $cek = Base64::urlDecode(self::$_testData['generated']['cek']);
        $iv = Base64::urlDecode(self::$_testData['generated']['iv']);
        $key_algo = AESKWAlgorithm::fromJWK($jwk, $header);
        $enc_algo = EncryptionAlgorithmFactory::algoByName(
            self::$_testData['input']['enc']);
        $zip_algo = CompressionFactory::algoByName(
            self::$_testData['input']['zip']);
        $jwe = JWE::encrypt($payload, $key_algo, $enc_algo, $zip_algo, $header, $cek, $iv);
        $this->assertInstanceOf(JWE::class, $jwe);
        $this->assertEquals(self::$_testData['output']['compact'],
            $jwe->toCompact());
        return $jwe;
    }
}
