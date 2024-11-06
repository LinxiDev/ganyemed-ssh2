package ch.ethz.ssh2.jce;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AES192CBC extends AES128CBC {
   private static final int ivsize = 16;
   private static final int bsize = 24;
   private Cipher cipher;

   public int getIVSize() {
      return 16;
   }

   public int getBlockSize() {
      return 24;
   }

   public void init(int mode, byte[] key, byte[] iv) throws Exception {
      byte[] tmp;
      if (iv.length > 16) {
         tmp = new byte[16];
         System.arraycopy(iv, 0, tmp, 0, tmp.length);
         iv = tmp;
      }

      if (key.length > 24) {
         tmp = new byte[24];
         System.arraycopy(key, 0, tmp, 0, tmp.length);
         key = tmp;
      }

      try {
         SecretKeySpec keyspec = new SecretKeySpec(key, "AES");
         this.cipher = Cipher.getInstance("AES/CBC/NoPadding");
         this.cipher.init(mode == 1 ? 1 : 2, keyspec, new IvParameterSpec(iv));
      } catch (Exception var6) {
         this.cipher = null;
         throw var6;
      }
   }

   public void update(byte[] foo, int s1, int len, byte[] bar, int s2) throws Exception {
      this.cipher.update(foo, s1, len, bar, s2);
   }

   public boolean isCBC() {
      return true;
   }
}