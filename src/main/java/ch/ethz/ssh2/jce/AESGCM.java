package ch.ethz.ssh2.jce;

import ch.ethz.ssh2.Cipher;
import java.nio.ByteBuffer;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

abstract class AESGCM implements Cipher {
   private static final int ivsize = 16;
   private static final int tagsize = 16;
   private javax.crypto.Cipher cipher;
   private SecretKeySpec keyspec;
   private int mode;
   private ByteBuffer iv;
   private long initcounter;

   public int getIVSize() {
      return 16;
   }

   public int getTagSize() {
      return 16;
   }

   public void init(int mode, byte[] key, byte[] iv) throws Exception {
      byte[] tmp;
      if (iv.length > 12) {
         tmp = new byte[12];
         System.arraycopy(iv, 0, tmp, 0, tmp.length);
         iv = tmp;
      }

      int bsize = this.getBlockSize();
      if (key.length > bsize) {
         tmp = new byte[bsize];
         System.arraycopy(key, 0, tmp, 0, tmp.length);
         key = tmp;
      }

      this.mode = mode == 0 ? 1 : 2;
      this.iv = ByteBuffer.wrap(iv);
      this.initcounter = this.iv.getLong(4);

      try {
         this.keyspec = new SecretKeySpec(key, "AES");
         this.cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
         this.cipher.init(this.mode, this.keyspec, new GCMParameterSpec(128, iv));
      } catch (Exception var7) {
         this.cipher = null;
         this.keyspec = null;
         this.iv = null;
         throw var7;
      }
   }

   public void update(byte[] foo, int s1, int len, byte[] bar, int s2) throws Exception {
      this.cipher.update(foo, s1, len, bar, s2);
   }

   public void updateAAD(byte[] foo, int s1, int len) throws Exception {
      this.cipher.updateAAD(foo, s1, len);
   }

   public void doFinal(byte[] foo, int s1, int len, byte[] bar, int s2) throws Exception {
      this.cipher.doFinal(foo, s1, len, bar, s2);
      long newcounter = this.iv.getLong(4) + 1L;
      if (newcounter == this.initcounter) {
         throw new IllegalStateException("GCM IV would be reused");
      } else {
         this.iv.putLong(4, newcounter);
         this.cipher.init(this.mode, this.keyspec, new GCMParameterSpec(128, this.iv.array()));
      }
   }

   public boolean isCBC() {
      return false;
   }

   public boolean isAEAD() {
      return true;
   }
}
