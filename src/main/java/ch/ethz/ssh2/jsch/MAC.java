package ch.ethz.ssh2.jsch;

public interface MAC {
   String getName();

   int getBlockSize();

   void init(byte[] var1) throws Exception;

   void update(byte[] var1, int var2, int var3);

   void update(int var1);

   void doFinal(byte[] var1, int var2);

   default boolean isEtM() {
      return false;
   }
}
