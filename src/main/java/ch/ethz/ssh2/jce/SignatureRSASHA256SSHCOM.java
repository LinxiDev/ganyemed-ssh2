package ch.ethz.ssh2.jce;

public class SignatureRSASHA256SSHCOM extends SignatureRSAN {
   String getName() {
      return "ssh-rsa-sha256@ssh.com";
   }
}
