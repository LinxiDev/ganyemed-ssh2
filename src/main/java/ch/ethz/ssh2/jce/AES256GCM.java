package ch.ethz.ssh2.jce;

public class AES256GCM extends AESGCM {
   private static final int bsize = 32;

   public int getBlockSize() {
      return 32;
   }
}
