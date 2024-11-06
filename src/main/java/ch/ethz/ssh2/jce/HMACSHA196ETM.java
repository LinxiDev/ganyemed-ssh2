package ch.ethz.ssh2.jce;

public class HMACSHA196ETM extends HMACSHA196 {
   public HMACSHA196ETM() {
      this.name = "hmac-sha1-96-etm@openssh.com";
      this.etm = true;
   }
}
