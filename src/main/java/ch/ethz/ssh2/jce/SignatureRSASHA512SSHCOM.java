package ch.ethz.ssh2.jce;

public class SignatureRSASHA512SSHCOM extends SignatureRSAN {
   String getName() {
      return "ssh-rsa-sha512@ssh.com";
   }
}
