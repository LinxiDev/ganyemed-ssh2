package ch.ethz.ssh2.jce;

public class HMACSHA256SSHCOM extends HMAC {
   public HMACSHA256SSHCOM() {
      this.name = "hmac-sha256@ssh.com";
      this.bsize = 16;
      this.algorithm = "HmacSHA256";
   }

   public int getBlockSize() {
      return 32;
   }
}
