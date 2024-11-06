package ch.ethz.ssh2.jce;

public class ECDH256 extends ECDHN {
   public void init() throws Exception {
      super.init(256);
   }
}
