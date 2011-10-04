<?php
/**
 * P5K
 *
 * For use where bcrypt is unavailable! (i.e., on servers that shockingly
 * haven't upgraded to PHP 5.3). If you're on PHP 5.3 or newer, use bcrypt
 * instead! I recommend phpass.
 *
 * Library to assist the storage and checking of hashed passwords using
 * a PBKDF2 implementation with 1000 rounds of HMAC-SHA256 and a 64-bit
 * salt derived from /dev/random. (These are the defaults. You can make it
 * less secure if you like by altering the pbkdf2 and salt parameters
 * default values.)
 *
 * P5K::make('password') returns a string in the pattern:
 * $p5k2$ [hex rounds] $ [base64 encoded salt] $ [base64 encoded derived key]
 *
 * P5K::check can be passed a password to check and a previous value of
 * P5K::make to check it against. Returns TRUE if the password matches.
 *
 * With the default setup, you can store the output of PBKDF2H::make in a
 * CHAR(65) field. Obviously, you can change the salt size, the number of
 * rounds, or even the key length, without affecting existing hashes in
 * the database.
 */
class P5K {

/**
 * Check a password against a previously generated extended PBKDF2 hash
 * value.
 *
 * @param string $p password to check
 * @param string $v previous value of PBKDF2H::make
 * @return boolean true if password matches hash in value
 */
	public function check($p, $v) {
		// Check that the hash follows the P5K2 format
		if (substr($v, 0, 6) != '$p5k2$') {
			return false;
		}
		
		list( , , $c, $s, $h) = explode('$', $v);
		
		$s = P5K::urlsafe_base64_decode($s);
		$h = P5K::urlsafe_base64_decode($h);
		$c = hexdec($c);
		
		$kl = strlen($h);
		
		return P5K::pbkdf2($p, $s, $c, $kl) == $h;
	}

/**
 * Create an extended PBKDF2 hash value, with "$p5k2$" as the first
 * characters as a flag in your DB (in case you decide to use a
 * different hashing method further down the road).
 *
 * @param string $p password to hash
 * @param int $ss size of salt to generate in bits (OPTIONAL)
 * @param int $c number of rounds to use (OPTIONAL)
 * @param int $kl derived key length (OPTIONAL)
 * @return string base64 encoded salt and password separated by '$'
 */
	public function make($p, $ss = 64, $c = 1000, $kl = 32) {
		$s = P5K::salt($ss / 8);
		$h = P5K::pbkdf2($p, $s, $c, $kl);
		
		return '$p5k2$' . dechex($c) . '$' . P5K::urlsafe_base64_encode($s) . '$' . P5K::urlsafe_base64_encode($h);
	}

/**
 * PBKDF2 Implementation (described in RFC 2898).
 *
 * I believe Andrew Johnson may be the originator of this code. If
 * I'm wrong about that, please let me know so I can put the
 * correct attribution in here.
 *
 * @param string $p password
 * @param string $s salt
 * @param int $c iteration count (use 1000 or higher) (OPTIONAL)
 * @param int $kl derived key length (OPTIONAL)
 * @param string $a hash algorithm (OPTIONAL)
 * @return string derived key
 */
	public function pbkdf2($p, $s, $c = 1000, $kl = 32, $a = 'sha256') {
		$hl = strlen(hash($a, null, true)); # Hash length
		$kb = ceil($kl / $hl);              # Key blocks to compute
		$dk = '';                           # Derived key
		
		// Create key
		for ($block = 1; $block <= $kb; $block ++) {
			// Initial hash for this block
			$ib = $b = hash_hmac($a, $s . pack('N', $block), $p, true);
			
			// Perform block iterations
			for ($i = 1; $i < $c; $i++) {
				// XOR each iterate
				$ib ^= ($b = hash_hmac($a, $b, $p, true));
			}
			
			$dk .= $ib; # Append iterated block
		}
		
		// Return derived key of correct length
		return substr($dk, 0, $kl);
	}

/**
 * Generate a cryptographically secure salt using /dev/random.
 *
 * @param int $b number of bytes to read from /dev/random (OPTIONAL)
 * @return string salt
 */
	public function salt($b = 16) {
		// The default source for mcrypt_create_iv is MCRYPT_DEV_RANDOM.
		// On Windows, you'll need to use MCRYPT_RAND instead.
		$salt = mcrypt_create_iv($b, MCRYPT_DEV_RANDOM);
		
		if (empty($salt)) {
			trigger_error('mcrypt_create_iv returned an empty value!', E_USER_ERROR);
		}
		
		return $salt;
	}

/**
 * URL-safe base64 decoding (compatible with Python's base64_urlsafe).
 *
 * @param string $s URL-safe base64 encoded string
 * @return string decoded data
 */
	public function urlsafe_base64_decode($s) {
		$d = str_replace(array('-','_'), array('+','/'), $s);
		
		$m = strlen($d) % 4;
		if ($m) $d .= substr('====', $m);
		
		return base64_decode($d);
	}

/**
 * URL-safe base64 encoding (compatible with Python's base64_urlsafe).
 *
 * @param string $s String to encode in Base64
 * @return string Base64 encoded data
 */
	public function urlsafe_base64_encode($s) {
		return str_replace(array('+','/','='), array('-','_',''), base64_encode($s));
	}

}
