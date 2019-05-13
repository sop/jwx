<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWE\CompressionAlgorithm\DeflateAlgorithm;
use Sop\JWX\JWE\EncryptionAlgorithm\A128CBCHS256Algorithm;
use Sop\JWX\JWE\EncryptionAlgorithm\A128GCMAlgorithm;
use Sop\JWX\JWE\JWE;
use Sop\JWX\JWE\KeyAlgorithm\A128KWAlgorithm;
use Sop\JWX\JWE\KeyAlgorithm\DirectCEKAlgorithm;
use Sop\JWX\JWE\KeyManagementAlgorithm;
use Sop\JWX\JWK\JWKSet;
use Sop\JWX\JWK\Parameter\KeyIDParameter as JWKID;
use Sop\JWX\JWK\Symmetric\SymmetricKeyJWK;
use Sop\JWX\JWT\Header\Header;
use Sop\JWX\JWT\Header\JOSE;
use Sop\JWX\JWT\Parameter\JWTParameter;
use Sop\JWX\JWT\Parameter\KeyIDParameter as JWTID;

/**
 * @group jwe
 *
 * @internal
 */
class JWETest extends TestCase
{
    const PAYLOAD = 'PAYLOAD';

    const KEY_ID = 'id';

    const CEK = '123456789 123456789 123456789 12';

    private static $_keyAlgo;

    private static $_encAlgo;

    public static function setUpBeforeClass(): void
    {
        self::$_keyAlgo = new DirectCEKAlgorithm(self::CEK);
        self::$_encAlgo = new A128CBCHS256Algorithm();
    }

    public static function tearDownAfterClass(): void
    {
        self::$_keyAlgo = null;
        self::$_encAlgo = null;
    }

    public function testEncrypt()
    {
        $jwe = JWE::encrypt(self::PAYLOAD, self::$_keyAlgo, self::$_encAlgo,
            null, new Header(new JWTID(self::KEY_ID)));
        $this->assertInstanceOf(JWE::class, $jwe);
        return $jwe;
    }

    /**
     * @depends testEncrypt
     *
     * @param JWE $jwe
     */
    public function testDecrypt(JWE $jwe)
    {
        $payload = $jwe->decrypt(self::$_keyAlgo, self::$_encAlgo);
        $this->assertEquals(self::PAYLOAD, $payload);
    }

    /**
     * @depends testEncrypt
     *
     * @param JWE $jwe
     */
    public function testDecryptInvalidAlgo(JWE $jwe)
    {
        $this->expectException(\UnexpectedValueException::class);
        $jwe->decrypt(new A128KWAlgorithm(str_repeat("\0", 16)), self::$_encAlgo);
    }

    /**
     * @depends testEncrypt
     *
     * @param JWE $jwe
     */
    public function testDecryptInvalidEncAlgo(JWE $jwe)
    {
        $this->expectException(\UnexpectedValueException::class);
        $jwe->decrypt(self::$_keyAlgo, new A128GCMAlgorithm());
    }

    /**
     * @depends testEncrypt
     *
     * @param JWE $jwe
     */
    public function testDecryptWithJWK(JWE $jwe)
    {
        $jwk = SymmetricKeyJWK::fromKey(self::CEK);
        $payload = $jwe->decryptWithJWK($jwk);
        $this->assertEquals(self::PAYLOAD, $payload);
    }

    /**
     * @depends testEncrypt
     *
     * @param JWE $jwe
     */
    public function testDecryptWithJWKSet(JWE $jwe)
    {
        $jwk = SymmetricKeyJWK::fromKey(self::CEK)->withParameters(
            new JWKID(self::KEY_ID));
        $payload = $jwe->decryptWithJWKSet(new JWKSet($jwk));
        $this->assertEquals(self::PAYLOAD, $payload);
    }

    /**
     * @depends testEncrypt
     *
     * @param JWE $jwe
     */
    public function testDecryptWithJWKSetNoKeys(JWE $jwe)
    {
        $this->expectException(\RuntimeException::class);
        $jwe->decryptWithJWKSet(new JWKSet());
    }

    /**
     * @depends testEncrypt
     *
     * @param JWE $jwe
     */
    public function testHeader(JWE $jwe)
    {
        $header = $jwe->header();
        $this->assertInstanceOf(JOSE::class, $header);
    }

    /**
     * @depends testEncrypt
     *
     * @param JWE $jwe
     */
    public function testEncryptedKey(JWE $jwe)
    {
        $this->assertEquals('', $jwe->encryptedKey());
    }

    /**
     * @depends testEncrypt
     *
     * @param JWE $jwe
     */
    public function testIV(JWE $jwe)
    {
        $this->assertIsString($jwe->initializationVector());
    }

    /**
     * @depends testEncrypt
     *
     * @param JWE $jwe
     */
    public function testCiphertext(JWE $jwe)
    {
        $this->assertIsString($jwe->ciphertext());
    }

    /**
     * @depends testEncrypt
     *
     * @param JWE $jwe
     */
    public function testAuthTag(JWE $jwe)
    {
        $this->assertIsString($jwe->authenticationTag());
    }

    /**
     * @depends testEncrypt
     *
     * @param JWE $jwe
     */
    public function testToCompact(JWE $jwe)
    {
        $data = $jwe->toCompact();
        $this->assertIsString($data);
        return $data;
    }

    /**
     * @depends testEncrypt
     *
     * @param JWE $jwe
     */
    public function testToString(JWE $jwe)
    {
        $token = strval($jwe);
        $this->assertIsString($token);
    }

    /**
     * @depends testToCompact
     *
     * @param string $data
     */
    public function testFromCompact($data)
    {
        $jwe = JWE::fromCompact($data);
        $this->assertInstanceOf(JWE::class, $jwe);
    }

    public function testFromPartsFail()
    {
        $this->expectException(\UnexpectedValueException::class);
        JWE::fromParts([]);
    }

    public function testEncryptWithAll()
    {
        $zip_algo = new DeflateAlgorithm();
        $header = new Header(new JWTParameter('test', 'value'));
        static $iv = '0123456789abcdef';
        $jwe = JWE::encrypt(self::PAYLOAD, self::$_keyAlgo, self::$_encAlgo,
            $zip_algo, $header, self::CEK, $iv);
        $this->assertInstanceOf(JWE::class, $jwe);
        return $jwe;
    }

    /**
     * @depends testEncryptWithAll
     *
     * @param JWE $jwe
     */
    public function testDecryptWithAll(JWE $jwe)
    {
        $payload = $jwe->decrypt(self::$_keyAlgo, self::$_encAlgo);
        $this->assertEquals(self::PAYLOAD, $payload);
    }

    /**
     * @depends testEncryptWithAll
     *
     * @param JWE $jwe
     */
    public function testCustomParameter(JWE $jwe)
    {
        $this->assertEquals('value', $jwe->header()->get('test')->value());
    }

    public function testEncryptInvalidKeySize()
    {
        $this->expectException(\UnexpectedValueException::class);
        JWE::encrypt(self::PAYLOAD, self::$_keyAlgo, self::$_encAlgo, null, null, 'nope');
    }

    public function testEncryptInvalidIVSize()
    {
        $this->expectException(\UnexpectedValueException::class);
        JWE::encrypt(self::PAYLOAD, self::$_keyAlgo, self::$_encAlgo, null, null, null, 'nope');
    }

    public function testKeyEncryptUnsetsHeader()
    {
        $key_algo = new JWETest_EvilKeyAlgo();
        $this->expectException(\RuntimeException::class);
        JWE::encrypt(self::PAYLOAD, $key_algo, self::$_encAlgo);
    }
}

class JWETest_EvilKeyAlgo extends KeyManagementAlgorithm
{
    public function cekForEncryption(int $length): string
    {
        return str_repeat("\0", $length);
    }

    public function algorithmParamValue(): string
    {
        return 'test';
    }

    public function headerParameters(): array
    {
        return [];
    }

    protected function _encryptKey(string $key, Header &$header): string
    {
        $header = null;
        return $key;
    }

    protected function _decryptKey(string $ciphertext, Header $header): string
    {
        return $ciphertext;
    }
}
