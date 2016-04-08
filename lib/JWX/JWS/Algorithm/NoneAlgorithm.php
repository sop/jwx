<?php

namespace JWX\JWS\Algorithm;

use JWX\JWS\SignatureAlgorithm;


class NoneAlgorithm implements SignatureAlgorithm
{
	public function algorithmParamValue() {
		return "none";
	}
	
	public function computeSignature($data) {
		return "";
	}
	
	public function validateSignature($data, $signature) {
		return $signature === "";
	}
}
