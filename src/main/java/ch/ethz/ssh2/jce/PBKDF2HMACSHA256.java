package ch.ethz.ssh2.jce;

public class PBKDF2HMACSHA256 extends PBKDF2 {
   String getName() {
      return "PBKDF2WithHmacSHA256";
   }
}
