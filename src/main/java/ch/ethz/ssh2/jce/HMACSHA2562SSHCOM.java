package ch.ethz.ssh2.jce;

public class HMACSHA2562SSHCOM extends HMAC {
   public HMACSHA2562SSHCOM() {
      this.name = "hmac-sha256-2@ssh.com";
      this.bsize = 32;
      this.algorithm = "HmacSHA256";
   }
}
