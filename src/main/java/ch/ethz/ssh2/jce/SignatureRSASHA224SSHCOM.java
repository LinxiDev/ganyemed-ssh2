package ch.ethz.ssh2.jce;

public class SignatureRSASHA224SSHCOM extends SignatureRSAN {
   String getName() {
      return "ssh-rsa-sha224@ssh.com";
   }
}
