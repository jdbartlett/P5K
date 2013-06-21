# Deprecated

This library was written for situations where PHP >= 5.3 is
unavailable. That should no longer be the case anywhere ever. If your
server is running an older version of PHP, please update it!

On newer versions of PHP, please use bcrypt instead. As of PHP 5.5
[the password_hash function](http://us1.php.net/manual/en/function.password-hash.php)
is built in, otherwise use [phpass](http://www.openwall.com/phpass/)
for help generating secure random salts. If you've used my P5K
library in the past, it will continue to work and you can use
its signature to check whether individual password hashes are in the
bcrypt or P5K format. I recommend, however, rehashing users'
passwords through bcrypt when they next log in.

# P5K

Library to assist the storage and checking of hashed passwords using
a PBKDF2 implementation with 1000 rounds of HMAC-SHA256 and a 64-bit
salt derived from `/dev/random`. (These are the defaults. You can make
it less secure if you like by altering the pbkdf2 and salt parameters
default values.)

For use where bcrypt is unavailable (i.e., on servers that shockingly
haven't upgraded to PHP 5.3). If you're on PHP 5.3 or newer, use bcrypt
instead!

`P5K::make('password')` returns a string in the pattern:

  $p5k2$[hex rounds]$[base64 encoded salt]$[base64 encoded derived key]

`P5K::check` can be passed a password to validate, and a previous
value of `P5K::make` to check it against. Returns `TRUE` if the
password matches.

With the default setup, you can store the output of `PBKDF2H::make`
in a CHAR(65) field. Obviously, you can change the salt size, the
number of rounds, or even the key length, without affecting existing
hashes in the database.
