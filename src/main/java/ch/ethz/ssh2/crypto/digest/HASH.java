package ch.ethz.ssh2.crypto.digest;

public interface HASH {
   void init() throws Exception;

   int getBlockSize();

   void update(byte[] var1, int var2, int var3) throws Exception;

   byte[] digest() throws Exception;

   String name();
}
