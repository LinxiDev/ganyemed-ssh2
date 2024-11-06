package ch.ethz.ssh2.jce;

public class HMACSHA1ETM extends HMACSHA1 {
   public HMACSHA1ETM() {
      this.name = "hmac-sha1-etm@openssh.com";
      this.etm = true;
   }
}
