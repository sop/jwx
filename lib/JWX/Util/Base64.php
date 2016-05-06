<?php

namespace JWX\Util;


/**
 * Class offering Base64 encoding and decoding.
 */
class Base64
{
	/**
	 * Encode a string using base64url variant.
	 *
	 * @link https://en.wikipedia.org/wiki/Base64#URL_applications
	 * @param string $data
	 * @return string
	 */
	public static function urlEncode($data) {
		return strtr(rtrim(base64_encode($data), "="), "+/", "-_");
	}
	
	/**
	 * Decode a string using base64url variant.
	 *
	 * @link https://en.wikipedia.org/wiki/Base64#URL_applications
	 * @param string $data
	 * @throws \UnexpectedValueException
	 * @return string
	 */
	public static function urlDecode($data) {
		$data = strtr($data, "-_", "+/");
		switch (strlen($data) % 4) {
		case 0:
			break;
		case 2:
			$data .= "==";
			break;
		case 3:
			$data .= "=";
			break;
		default:
			throw new \UnexpectedValueException("Malformed base64url encoding.");
		}
		$data = base64_decode($data, true);
		if ($data === false) {
			throw new \UnexpectedValueException("Malformed base64 encoding.");
		}
		return $data;
	}
	
	/**
	 * Check whether string is validly base64url encoded.
	 *
	 * @link https://en.wikipedia.org/wiki/Base64#URL_applications
	 * @param string $data
	 * @return bool
	 */
	public static function isValidURLEncoding($data) {
		return preg_match('#[A-Za-z0-9\-_]*#', $data) == 1;
	}
}
