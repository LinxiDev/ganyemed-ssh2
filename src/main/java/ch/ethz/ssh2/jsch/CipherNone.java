package ch.ethz.ssh2.jsch;

class CipherNone implements Cipher {
   private static final int ivsize = 8;
   private static final int bsize = 16;

   public int getIVSize() {
      return 8;
   }

   public int getBlockSize() {
      return 16;
   }

   public void init(int mode, byte[] key, byte[] iv) throws Exception {
   }

   public void update(byte[] foo, int s1, int len, byte[] bar, int s2) throws Exception {
   }

   public boolean isCBC() {
      return false;
   }
}
