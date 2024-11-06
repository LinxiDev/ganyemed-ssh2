package ch.ethz.ssh2.jce;

public class SignatureRSA extends SignatureRSAN {
   String getName() {
      return "ssh-rsa";
   }
}
