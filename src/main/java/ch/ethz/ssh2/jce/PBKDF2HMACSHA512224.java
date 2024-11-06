package ch.ethz.ssh2.jce;

public class PBKDF2HMACSHA512224 extends PBKDF2 {
   String getName() {
      return "PBKDF2WithHmacSHA512/224";
   }
}
