package ch.ethz.ssh2.jce;

public class HMACMD5 extends HMAC {
   public HMACMD5() {
      this.name = "hmac-md5";
      this.bsize = 16;
      this.algorithm = "HmacMD5";
   }
}
