<?php

namespace JWX\Util;


class Base64
{
	/**
	 * Encode string using base64url variant
	 *
	 * @param string $data
	 * @return string
	 */
	public static function urlEncode($data) {
		return strtr(rtrim(base64_encode($data), "="), "+/", "-_");
	}
	
	/**
	 * Decode string using base64url variant
	 *
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
			throw new \UnexpectedValueException("Malformed base64url encoding");
		}
		$data = base64_decode($data, true);
		if ($data === false) {
			throw new \UnexpectedValueException("Malformed base64 encoding");
		}
		return $data;
	}
}
