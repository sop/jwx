<?php

use JWX\JWT\Header;
use JWX\JWT\Parameter\AlgorithmParameter;
use JWX\Util\Base64;
use JWX\JWK\RSA\RSAPrivateKeyJWK;
use JWX\JWS\Algorithm\RS256Algorithm;


/**
 * Test case for rfc7515 appendix A.2.
 * Example JWS Using RSASSA-PKCS1-v1_5 SHA-256
 *
 * @group example
 *
 * @link https://tools.ietf.org/html/rfc7515#appendix-A.2
 */
class JWSUsingRS256Test extends PHPUnit_Framework_TestCase
{
	private static $_claims = /* @formatter:off */
		'{"iss":"joe",' . "\r\n" .
		' "exp":1300819380,' . "\r\n" .
		' "http://example.com/is_root":true}'; /* @formatter:on */
	
	private static $_jwk = /* @formatter:off */
	'{"kty":"RSA",
 "n":"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddx'.
      'HmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMs'.
      'D1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSH'.
      'SXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdV'.
      'MTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8'.
      'NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ",
 "e":"AQAB",
 "d":"Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97I'.
      'jlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0'.
      'BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn'.
      '439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYT'.
      'CBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLh'.
      'BOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ",
 "p":"4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdi'.
      'YrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPG'.
      'BY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc",
 "q":"uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxa'.
      'ewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA'.
      '-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc",
 "dp":"BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3Q'.
      'CLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb'.
      '34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0",
 "dq":"h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa'.
      '7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-ky'.
      'NlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU",
 "qi":"IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2o'.
      'y26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLU'.
      'W0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U"
}'; /* @formatter:on */
	
	private static $_payloadBytes = [101, 121, 74, 104, 98, 71, 99, 105, 79, 
		105, 74, 83, 85, 122, 73, 49, 78, 105, 74, 57, 46, 101, 121, 74, 112, 99, 
		51, 77, 105, 79, 105, 74, 113, 98, 50, 85, 105, 76, 65, 48, 75, 73, 67, 
		74, 108, 101, 72, 65, 105, 79, 106, 69, 122, 77, 68, 65, 52, 77, 84, 107, 
		122, 79, 68, 65, 115, 68, 81, 111, 103, 73, 109, 104, 48, 100, 72, 65, 
		54, 76, 121, 57, 108, 101, 71, 70, 116, 99, 71, 120, 108, 76, 109, 78, 
		118, 98, 83, 57, 112, 99, 49, 57, 121, 98, 50, 57, 48, 73, 106, 112, 48, 
		99, 110, 86, 108, 102, 81];
	
	private static $_signatureBytes = [112, 46, 33, 137, 67, 232, 143, 209, 
		30, 181, 216, 45, 191, 120, 69, 243, 65, 6, 174, 27, 129, 255, 247, 115, 
		17, 22, 173, 209, 113, 125, 131, 101, 109, 66, 10, 253, 60, 150, 238, 
		221, 115, 162, 102, 62, 81, 102, 104, 123, 0, 11, 135, 34, 110, 1, 135, 
		237, 16, 115, 249, 69, 229, 130, 173, 252, 239, 22, 216, 90, 121, 142, 
		232, 198, 109, 219, 61, 184, 151, 91, 23, 208, 148, 2, 190, 237, 213, 
		217, 217, 112, 7, 16, 141, 178, 129, 96, 213, 248, 4, 12, 167, 68, 87, 
		98, 184, 31, 190, 127, 249, 217, 46, 10, 231, 111, 36, 242, 91, 51, 187, 
		230, 244, 74, 230, 30, 177, 4, 10, 203, 32, 4, 77, 62, 249, 18, 142, 212, 
		1, 48, 121, 91, 212, 189, 59, 65, 238, 202, 208, 102, 171, 101, 25, 129, 
		253, 228, 141, 247, 127, 55, 45, 195, 139, 159, 175, 221, 59, 239, 177, 
		139, 93, 163, 204, 60, 46, 176, 47, 158, 58, 65, 214, 18, 202, 173, 21, 
		145, 18, 115, 160, 95, 35, 185, 232, 56, 250, 175, 132, 157, 105, 132, 
		41, 239, 90, 30, 136, 121, 130, 54, 195, 212, 14, 96, 69, 34, 165, 68, 
		200, 242, 122, 122, 45, 184, 6, 99, 209, 108, 247, 202, 234, 86, 222, 64, 
		92, 178, 33, 90, 69, 178, 194, 85, 102, 181, 90, 193, 167, 72, 160, 112, 
		223, 200, 163, 42, 70, 149, 67, 208, 25, 238, 251, 71];
	
	public function testEncodeHeader() {
		static $expected = "eyJhbGciOiJSUzI1NiJ9";
		$header = new Header(
			new AlgorithmParameter(AlgorithmParameter::ALGO_RS256));
		$json = $header->toJSON();
		$data = Base64::urlEncode($json);
		$this->assertEquals($expected, $data);
		return $data;
	}
	
	/**
	 * @depends testEncodeHeader
	 *
	 * @param string $header
	 */
	public function testEncodePayload($header) {
		$data = Base64::urlEncode(self::$_claims);
		$payload = "$header.$data";
		$expected = implode("", array_map("chr", self::$_payloadBytes));
		$this->assertEquals($expected, $payload);
		return $payload;
	}
	
	/**
	 * @depends testEncodePayload
	 *
	 * @param string $payload
	 */
	public function testSign($payload) {
		$jwk = RSAPrivateKeyJWK::fromJSON(self::$_jwk);
		$algo = RS256Algorithm::fromPrivateKey($jwk);
		$signature = $algo->computeSignature($payload);
		$expected = implode("", array_map("chr", self::$_signatureBytes));
		$this->assertEquals($expected, $signature);
		return $signature;
	}
	
	/**
	 * @depends testEncodePayload
	 * @depends testSign
	 *
	 * @param string $payload
	 * @param string $signature
	 */
	public function testValidate($payload, $signature) {
		$jwk = RSAPrivateKeyJWK::fromJSON(self::$_jwk);
		$algo = RS256Algorithm::fromPublicKey($jwk->publicKey());
		$this->assertTrue($algo->validateSignature($payload, $signature));
	}
}
