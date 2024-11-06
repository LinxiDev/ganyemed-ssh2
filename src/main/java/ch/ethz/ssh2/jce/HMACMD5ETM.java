package ch.ethz.ssh2.jce;

public class HMACMD5ETM extends HMACMD5 {
   public HMACMD5ETM() {
      this.name = "hmac-md5-etm@openssh.com";
      this.etm = true;
   }
}
