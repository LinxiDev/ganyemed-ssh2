package ch.ethz.ssh2.jce;

public class SignatureRSASHA256 extends SignatureRSAN {
   String getName() {
      return "rsa-sha2-256";
   }
}
