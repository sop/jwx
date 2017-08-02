<?php

use JWX\JWE\JWE;
use JWX\JWE\EncryptionAlgorithm\EncryptionAlgorithmFactory;
use JWX\JWE\KeyAlgorithm\DirectCEKAlgorithm;
use JWX\JWK\Symmetric\SymmetricKeyJWK;
use JWX\JWT\Header\Header;
use JWX\Util\Base64;

class CookbookDirectEncWithAESGCMTest extends PHPUnit_Framework_TestCase
{
    private static $_testData;
    
    public static function setUpBeforeClass()
    {
        $json = file_get_contents(
            COOKBOOK_DIR . "/jwe/5_6.direct_encryption_using_aes-gcm.json");
        self::$_testData = json_decode($json, true);
    }
    
    public static function tearDownAfterClass()
    {
        self::$_testData = null;
    }
    
    public function testCreateJWK()
    {
        $jwk = SymmetricKeyJWK::fromArray(self::$_testData["input"]["key"]);
        $this->assertInstanceOf(SymmetricKeyJWK::class, $jwk);
        return $jwk;
    }
    
    public function testHeader()
    {
        $header = Header::fromArray(
            self::$_testData["encrypting_content"]["protected"]);
        $encoded = Base64::urlEncode($header->toJSON());
        $this->assertEquals(
            self::$_testData["encrypting_content"]["protected_b64u"], $encoded);
        return $header;
    }
    
    /**
     * @depends testCreateJWK
     * @depends testHeader
     */
    public function testContentEncryption(SymmetricKeyJWK $jwk, Header $header)
    {
        $plaintext = self::$_testData["input"]["plaintext"];
        $iv = Base64::urlDecode(self::$_testData["generated"]["iv"]);
        $aad = Base64::urlEncode($header->toJSON());
        $cek = DirectCEKAlgorithm::fromJWK($jwk, $header)->cek();
        $algo = EncryptionAlgorithmFactory::algoByName(
            self::$_testData["input"]["enc"]);
        list($ciphertext, $auth_tag) = $algo->encrypt($plaintext, $cek, $iv,
            $aad);
        $this->assertEquals(
            self::$_testData["encrypting_content"]["ciphertext"],
            Base64::urlEncode($ciphertext));
        $this->assertEquals(self::$_testData["encrypting_content"]["tag"],
            Base64::urlEncode($auth_tag));
    }
    
    /**
     * @depends testCreateJWK
     * @depends testHeader
     */
    public function testCreateJWE(SymmetricKeyJWK $jwk, Header $header)
    {
        $payload = self::$_testData["input"]["plaintext"];
        $iv = Base64::urlDecode(self::$_testData["generated"]["iv"]);
        $key_algo = DirectCEKAlgorithm::fromJWK($jwk, $header);
        $enc_algo = EncryptionAlgorithmFactory::algoByName(
            self::$_testData["input"]["enc"]);
        $jwe = JWE::encrypt($payload, $key_algo, $enc_algo, null, $header, null,
            $iv);
        $this->assertInstanceOf(JWE::class, $jwe);
        $this->assertEquals(self::$_testData["output"]["compact"],
            $jwe->toCompact());
        return $jwe;
    }
}
