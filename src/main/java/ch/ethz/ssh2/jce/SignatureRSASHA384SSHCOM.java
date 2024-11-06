package ch.ethz.ssh2.jce;

public class SignatureRSASHA384SSHCOM extends SignatureRSAN {
   String getName() {
      return "ssh-rsa-sha384@ssh.com";
   }
}
