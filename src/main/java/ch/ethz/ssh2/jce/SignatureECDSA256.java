package ch.ethz.ssh2.jce;

public class SignatureECDSA256 extends SignatureECDSAN {
   String getName() {
      return "ecdsa-sha2-nistp256";
   }
}
