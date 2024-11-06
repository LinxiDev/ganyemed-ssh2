package ch.ethz.ssh2.jce;

public class PBKDF2HMACSHA512 extends PBKDF2 {
   String getName() {
      return "PBKDF2WithHmacSHA512";
   }
}
