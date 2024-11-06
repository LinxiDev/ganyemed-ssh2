package ch.ethz.ssh2.jce;

public class HMACSHA224SSHCOM extends HMAC {
   public HMACSHA224SSHCOM() {
      this.name = "hmac-sha224@ssh.com";
      this.bsize = 28;
      this.algorithm = "HmacSHA224";
   }
}
