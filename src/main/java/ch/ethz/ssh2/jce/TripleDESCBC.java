package ch.ethz.ssh2.jce;

import ch.ethz.ssh2.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;

public class TripleDESCBC implements Cipher {
   private static final int ivsize = 8;
   private static final int bsize = 24;
   private javax.crypto.Cipher cipher;

   public int getIVSize() {
      return 8;
   }

   public int getBlockSize() {
      return 24;
   }

   public void init(int mode, byte[] key, byte[] iv) throws Exception {
      byte[] tmp;
      if (iv.length > 8) {
         tmp = new byte[8];
         System.arraycopy(iv, 0, tmp, 0, tmp.length);
         iv = tmp;
      }

      if (key.length > 24) {
         tmp = new byte[24];
         System.arraycopy(key, 0, tmp, 0, tmp.length);
         key = tmp;
      }

      try {
         this.cipher = javax.crypto.Cipher.getInstance("DESede/CBC/NoPadding");
         DESedeKeySpec keyspec = new DESedeKeySpec(key);
         SecretKeyFactory keyfactory = SecretKeyFactory.getInstance("DESede");
         SecretKey _key = keyfactory.generateSecret(keyspec);
         this.cipher.init(mode == 0 ? 1 : 2, _key, new IvParameterSpec(iv));
      } catch (Exception var8) {
         this.cipher = null;
         throw var8;
      }
   }

   public void update(byte[] foo, int s1, int len, byte[] bar, int s2) throws Exception {
      this.cipher.update(foo, s1, len, bar, s2);
   }

   public boolean isCBC() {
      return true;
   }
}
