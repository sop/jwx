<?php

use JWX\JWE\EncryptionAlgorithm\A128CBCHS256Algorithm;
use JWX\JWE\JWE;
use JWX\JWE\KeyAlgorithm\A128KWAlgorithm;
use JWX\JWK\JWK;
use JWX\JWK\Parameter\RegisteredJWKParameter;
use JWX\JWK\Symmetric\SymmetricKeyJWK;
use JWX\JWT\Header\Header;
use JWX\JWT\Header\JOSE;
use JWX\Util\Base64;


/**
 * Test case for RFC 7516 appendix A.3.
 * Example JWE Using AES Key Wrap and AES_128_CBC_HMAC_SHA_256
 *
 * @group example
 *
 * @link https://tools.ietf.org/html/rfc7516#appendix-A.3
 */
class JWEUsingA128KWAndA128CBCTest extends PHPUnit_Framework_TestCase
{
	private static $_plaintextBytes = [76, 105, 118, 101, 32, 108, 111, 110, 
		103, 32, 97, 110, 100, 32, 112, 114, 111, 115, 112, 101, 114, 46];
	
	private static $_headerJSON = '{"alg":"A128KW","enc":"A128CBC-HS256"}';
	
	private static $_cekBytes = [4, 211, 31, 197, 84, 157, 252, 254, 11, 
		100, 157, 250, 63, 170, 106, 206, 107, 124, 212, 45, 111, 107, 9, 219, 
		200, 177, 0, 240, 143, 156, 44, 207];
	
	private static $_jwkJSON = '{"kty":"oct","k":"GawgguFyGrWKav7AX4VKUg"}';
	
	private static $_ivBytes = [3, 22, 60, 12, 43, 67, 104, 105, 108, 108, 
		105, 99, 111, 116, 104, 101];
	
	public function testEncodeJOSE() {
		static $expected = 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0';
		$header = Header::fromJSON(self::$_headerJSON);
		$jose = new JOSE($header);
		$header = Base64::urlEncode($jose->toJSON());
		$this->assertEquals($expected, $header);
		return $header;
	}
	
	public function testJWKKey() {
		$jwk = SymmetricKeyJWK::fromJSON(self::$_jwkJSON);
		$key = $jwk->get(RegisteredJWKParameter::P_K)->key();
		$this->assertEquals(16, strlen($key));
		return $key;
	}
	
	/**
	 * @depends testJWKKey
	 *
	 * @param string $kek
	 */
	public function testEncryptCEK($kek) {
		static $expected = "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ";
		$cek = implode("", array_map("chr", self::$_cekBytes));
		$algo = new A128KWAlgorithm($kek);
		$data = $algo->encrypt($cek);
		$this->assertEquals($expected, Base64::urlEncode($data));
		return $data;
	}
	
	/**
	 * @depends testEncodeJOSE
	 *
	 * @param string $header
	 */
	public function testEncodeAAD($header) {
		static $expectedBytes = [101, 121, 74, 104, 98, 71, 99, 105, 79, 
			105, 74, 66, 77, 84, 73, 52, 83, 49, 99, 105, 76, 67, 74, 108, 98, 
			109, 77, 105, 79, 105, 74, 66, 77, 84, 73, 52, 81, 48, 74, 68, 76, 
			85, 104, 84, 77, 106, 85, 50, 73, 110, 48];
		$expected = implode("", array_map("chr", $expectedBytes));
		$this->assertEquals($expected, $header);
		return $header;
	}
	
	/**
	 * @depends testEncodeAAD
	 *
	 * @param string $aad
	 */
	public function testEncryptContent($aad) {
		static $expectedCiphertextBytes = [40, 57, 83, 181, 119, 33, 133, 
			148, 198, 185, 243, 24, 152, 230, 6, 75, 129, 223, 127, 19, 210, 82, 
			183, 230, 168, 33, 215, 104, 143, 112, 56, 102];
		static $expectedAuthTagBytes = [83, 73, 191, 98, 104, 205, 211, 128, 
			201, 189, 199, 133, 32, 38, 194, 85];
		$expectedCiphertext = implode("", 
			array_map("chr", $expectedCiphertextBytes));
		$expectedAuthTag = implode("", array_map("chr", $expectedAuthTagBytes));
		$plaintext = implode("", array_map("chr", self::$_plaintextBytes));
		$key = implode("", array_map("chr", self::$_cekBytes));
		$iv = implode("", array_map("chr", self::$_ivBytes));
		$algo = new A128CBCHS256Algorithm();
		list($data, $auth_tag) = $algo->encrypt($plaintext, $key, $iv, $aad);
		$this->assertEquals($expectedCiphertext, $data);
		$this->assertEquals($expectedAuthTag, $auth_tag);
		return [$data, $auth_tag];
	}
	
	/**
	 * @depends testEncryptContent
	 * @depends testEncryptCEK
	 * @depends testJWKKey
	 */
	public function testDecrypt($data, $enc_key, $kek) {
		$header = Base64::urlEncode(self::$_headerJSON);
		$enc_key_b64 = Base64::urlEncode($enc_key);
		$iv = Base64::urlEncode(implode("", array_map("chr", self::$_ivBytes)));
		$ciphertext = Base64::urlEncode($data[0]);
		$tag = Base64::urlEncode($data[1]);
		$token = "$header.$enc_key_b64.$iv.$ciphertext.$tag";
		$jwe = JWE::fromCompact($token);
		$key_algo = new A128KWAlgorithm($kek);
		$enc_algo = new A128CBCHS256Algorithm();
		$plaintext = $jwe->decrypt($key_algo, $enc_algo);
		$expected = implode("", array_map("chr", self::$_plaintextBytes));
		$this->assertEquals($expected, $plaintext);
	}
}