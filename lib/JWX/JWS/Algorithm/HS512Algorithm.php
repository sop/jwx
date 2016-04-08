<?php

namespace JWX\JWS\Algorithm;


class HS512Algorithm extends HMACAlgorithm
{
	protected function _hashAlgo() {
		return "sha512";
	}
	
	public function algorithmParamValue() {
		return "HS512";
	}
}
