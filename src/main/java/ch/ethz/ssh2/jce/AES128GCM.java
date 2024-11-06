package ch.ethz.ssh2.jce;

public class AES128GCM extends AESGCM {
   private static final int bsize = 16;

   public int getBlockSize() {
      return 16;
   }
}
