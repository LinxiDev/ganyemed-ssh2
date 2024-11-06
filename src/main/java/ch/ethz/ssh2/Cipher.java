package ch.ethz.ssh2;

public interface Cipher {
   int ENCRYPT_MODE = 0;
   int DECRYPT_MODE = 1;

   int getIVSize();

   int getBlockSize();

   default int getTagSize() {
      return 0;
   }

   void init(int var1, byte[] var2, byte[] var3) throws Exception;

   default void update(int foo) throws Exception {
   }

   void update(byte[] var1, int var2, int var3, byte[] var4, int var5) throws Exception;

   default void updateAAD(byte[] foo, int s1, int len) throws Exception {
   }

   default void doFinal(byte[] foo, int s1, int len, byte[] bar, int s2) throws Exception {
   }

   boolean isCBC();

   default boolean isAEAD() {
      return false;
   }

   default boolean isChaCha20() {
      return false;
   }
}
