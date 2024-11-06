package ch.ethz.ssh2.jce;

public class SignatureECDSA384 extends SignatureECDSAN {
   String getName() {
      return "ecdsa-sha2-nistp384";
   }
}
