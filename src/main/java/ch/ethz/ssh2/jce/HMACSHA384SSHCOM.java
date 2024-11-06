package ch.ethz.ssh2.jce;

public class HMACSHA384SSHCOM extends HMAC {
   public HMACSHA384SSHCOM() {
      this.name = "hmac-sha384@ssh.com";
      this.bsize = 48;
      this.algorithm = "HmacSHA384";
   }
}
