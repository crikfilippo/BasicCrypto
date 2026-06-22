<?php

namespace BasicEncryptedString;

class BasicEncryptedString implements \Stringable
{

    private static bool $isReady = false;
    private static string $saltedKey;
    private static string $cipherAlgo;
    private static int $initializationVectorLength;
    private static string $hashAlgo;
	private static ?string $plainValue;
	private static ?string $encryptedValue;
	
	public function __construct(
		string $plainValue, 
		?string $encryptedValue = null,
		bool $isDecrypting = false
	 ){
        if( ! self::$isReady){ throw new \Exception('EncryptedString not initialized, please use ::setParams()'); }
		self::$plainValue = $plainValue;
		self::$encryptedValue = ! is_null($encryptedValue) ? $encryptedValue : ((string) self::encrypt($plainValue));
		$this->value = $isDecrypting ? self::$plainValue : self::$encryptedValue;
	}
	
	public function __toString(): string {
        return $this->value;
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
    public static function encrypt(?string $plainValue = null) : self {

        if( ! self::$isReady){ throw new \Exception('EncryptedString not initialized, missing params.'); }
		
		if( is_null($plainValue) ){ $plainValue = self::$plainValue; }
        if(strlen(trim(($plainValue ?? ''))) == 0){ self::$plainValue = ''; self::$encryptedValue = '';	return new self('','');}
		self::$plainValue = $plainValue;
		
        $iv = openssl_random_pseudo_bytes(self::$initializationVectorLength);
        self::$encryptedValue = openssl_encrypt( $plainValue, self::$cipherAlgo,  substr(self::$saltedKey, 0, 32), 0,  $iv );
        self::$encryptedValue = ($iv . self::$encryptedValue);
        self::$encryptedValue = base64_encode(self::$encryptedValue);
        
        return new self(self::$plainValue,self::$encryptedValue);
        
    }

    //DECRYPT
    public static function decrypt(?string $encryptedValue = null) : self {

        if( ! self::$isReady){ throw new \Exception('EncryptedString not initialized, missing params.'); }
		
		if( is_null($encryptedValue) ){ $encryptedValue = self::$encryptedValue; }
        if(strlen(trim(($encryptedValue ?? ''))) == 0){ self::$encryptedValue = ''; self::$plainValue = ''; return new self('',''); }
		self::$encryptedValue = $encryptedValue;
      
        self::$plainValue = base64_decode($encryptedValue);
        $iv = substr(self::$plainValue, 0, self::$initializationVectorLength);
        self::$plainValue = substr(self::$plainValue, self::$initializationVectorLength);
        self::$plainValue = openssl_decrypt( self::$plainValue, self::$cipherAlgo, substr(self::$saltedKey, 0, 32), 0, $iv );
        
        return new self(self::$plainValue,self::$encryptedValue,true);

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