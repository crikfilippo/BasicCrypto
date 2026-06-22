<?php

namespace BasicCrypto;

class BasicCrypto
{
    private static bool $isReady = false;
    private static string $saltedKey;
    private static string $cipherAlgo;
    private static int $initializationVectorLength;
    private static string $hashAlgo;
	
	public function __construct(){
        if( ! self::$isReady){ throw new \Exception('EncryptedString not initialized, please use ::setParams()'); }
	}

    //SET REQUIRED PARAMS
    public static function setParams(
        string $saltedKey,
        string $cipherAlgo = 'AES-256-CBC',
        int $initializationVectorLength = 16,
        string $hashAlgo = 'sha256'
     ){
        self::$saltedKey = $saltedKey;
        self::$cipherAlgo = $cipherAlgo;
        self::$initializationVectorLength = $initializationVectorLength;
        self::$hashAlgo = $hashAlgo;
        self::$isReady = true;
    }
    
    //ENCRYPT
    public static function encrypt(?string $plainValue = null) : ?string {

        if(strlen(trim(($plainValue ?? ''))) == 0){ return null; }
        $iv = openssl_random_pseudo_bytes(self::$initializationVectorLength);
        $encryptedValue = openssl_encrypt( $plainValue, self::$cipherAlgo,  substr(self::$saltedKey, 0, 32), 0,  $iv );
        $encryptedValue = ($iv . $encryptedValue);
        $encryptedValue = base64_encode($encryptedValue);
        return $encryptedValue;
        
    }

    //DECRYPT
    public static function decrypt(?string $encryptedValue = null) : ?string {

        if(strlen(trim(($encryptedValue ?? ''))) == 0){ return null; }
        $plainValue = base64_decode($encryptedValue);
        $iv = substr($plainValue, 0, self::$initializationVectorLength);
        $plainValue = substr($plainValue, self::$initializationVectorLength);
        $plainValue = openssl_decrypt( $plainValue, self::$cipherAlgo, substr(self::$saltedKey, 0, 32), 0, $iv );
        return $plainValue;

    }

    //[UTILITY] GENERATE AUTH KEY
    public static function genAuthKey(){
        return bin2hex(random_bytes(32));
    }

    //[UTILITY] GENERATE SALT
    public static function genSalt(){
        return bin2hex(random_bytes(10));
    }

    //[UTILITY] GENERATE SALTED KEY
    public static function genSaltedKey( ?string $hashAlgo = null, ?string $authKey = null, ?string $salt = null ){
        if( is_null($hashAlgo) ){ $hashAlgo = self::$hashAlgo; }
        if( is_null($authKey) ){ $authKey = self::genAuthKey(); }
        if( is_null($salt) ){ $salt = self::genSalt(); }
        $saltedKey = hash($hashAlgo, $authKey . $salt);
        return $saltedKey;
    }

    //[UTILITY] GET INITIALIZATION VECTOR LENGTH
    public static function getInitializationVectorLength( ?string $cipherAlgo = null){
        if( is_null($cipherAlgo) ){ $cipherAlgo = self::$cipherAlgo; }
        return openssl_cipher_iv_length($cipherAlgo);
    }


}
