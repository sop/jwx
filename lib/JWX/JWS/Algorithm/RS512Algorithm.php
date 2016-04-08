<?php

namespace JWX\JWS\Algorithm;


class RS512Algorithm extends RSAPKCS1Algorithm
{
	protected function _mdMethod() {
		return "sha512WithRSAEncryption";
	}
	
	public function algorithmParamValue() {
		return "RS512";
	}
}
