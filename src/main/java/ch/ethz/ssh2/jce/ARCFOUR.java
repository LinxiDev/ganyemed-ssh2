package ch.ethz.ssh2.jce;

import ch.ethz.ssh2.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class ARCFOUR implements Cipher {
   private static final int ivsize = 8;
   private static final int bsize = 16;
   private javax.crypto.Cipher cipher;

   public int getIVSize() {
      return 8;
   }

   public int getBlockSize() {
      return 16;
   }

   public void init(int mode, byte[] key, byte[] iv) throws Exception {
      if (key.length > 16) {
         byte[] tmp = new byte[16];
         System.arraycopy(key, 0, tmp, 0, tmp.length);
         key = tmp;
      }

      try {
         this.cipher = javax.crypto.Cipher.getInstance("RC4");
         SecretKeySpec _key = new SecretKeySpec(key, "RC4");
         this.cipher.init(mode == 0 ? 1 : 2, _key);
      } catch (Exception var6) {
         this.cipher = null;
         throw var6;
      }
   }

   public void update(byte[] foo, int s1, int len, byte[] bar, int s2) throws Exception {
      this.cipher.update(foo, s1, len, bar, s2);
   }

   public boolean isCBC() {
      return false;
   }
}
