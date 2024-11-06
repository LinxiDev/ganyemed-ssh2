package ch.ethz.ssh2.jce;

public class HMACSHA256ETM extends HMACSHA256 {
   public HMACSHA256ETM() {
      this.name = "hmac-sha2-256-etm@openssh.com";
      this.etm = true;
   }
}
