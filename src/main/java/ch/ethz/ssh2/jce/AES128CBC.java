package ch.ethz.ssh2.jce;

import ch.ethz.ssh2.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AES128CBC implements Cipher {
   private static final int ivsize = 16;
   private static final int bsize = 16;
   private javax.crypto.Cipher cipher;

   public int getIVSize() {
      return 16;
   }

   public int getBlockSize() {
      return 16;
   }

   public void init(int mode, byte[] key, byte[] iv) throws Exception {
      byte[] tmp;
      if (iv.length > 16) {
         tmp = new byte[16];
         System.arraycopy(iv, 0, tmp, 0, tmp.length);
         iv = tmp;
      }

      if (key.length > 16) {
         tmp = new byte[16];
         System.arraycopy(key, 0, tmp, 0, tmp.length);
         key = tmp;
      }

      try {
         SecretKeySpec keyspec = new SecretKeySpec(key, "AES");
         this.cipher = javax.crypto.Cipher.getInstance("AES/CBC/NoPadding");
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

   public int getTagSize() {
      return 0;
   }

   public void update(int foo) throws Exception {
   }

   public void updateAAD(byte[] foo, int s1, int len) throws Exception {
   }

   public void doFinal(byte[] foo, int s1, int len, byte[] bar, int s2) throws Exception {
   }

   public boolean isAEAD() {
      return false;
   }

   public boolean isChaCha20() {
      return false;
   }
}
