package ch.ethz.ssh2.jce;

public class SignatureRSASHA512 extends SignatureRSAN {
   String getName() {
      return "rsa-sha2-512";
   }
}
