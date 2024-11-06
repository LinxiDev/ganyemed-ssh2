package ch.ethz.ssh2.jce;

public class HMACMD596ETM extends HMACMD596 {
   public HMACMD596ETM() {
      this.name = "hmac-md5-96-etm@openssh.com";
      this.etm = true;
   }
}
