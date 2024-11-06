package ch.ethz.ssh2.jce;

public class HMACSHA512SSHCOM extends HMAC {
   public HMACSHA512SSHCOM() {
      this.name = "hmac-sha512@ssh.com";
      this.bsize = 64;
      this.algorithm = "HmacSHA512";
   }
}
