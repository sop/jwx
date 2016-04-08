<?php

namespace JWX\JWS\Algorithm;


class HS384Algorithm extends HMACAlgorithm
{
	protected function _hashAlgo() {
		return "sha384";
	}
	
	public function algorithmParamValue() {
		return "HS384";
	}
}
