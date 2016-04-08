<?php

namespace JWX\JWS\Algorithm;


class HS256Algorithm extends HMACAlgorithm
{
	protected function _hashAlgo() {
		return "sha256";
	}
	
	public function algorithmParamValue() {
		return "HS256";
	}
}
