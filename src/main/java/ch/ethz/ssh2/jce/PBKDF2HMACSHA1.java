package ch.ethz.ssh2.jce;

public class PBKDF2HMACSHA1 extends PBKDF2 {
   String getName() {
      return "PBKDF2WithHmacSHA1";
   }
}