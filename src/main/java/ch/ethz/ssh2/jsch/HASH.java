package ch.ethz.ssh2.jsch;

public interface HASH {
   void init() throws Exception;

   int getBlockSize();

   void update(byte[] var1, int var2, int var3) throws Exception;

   byte[] digest() throws Exception;

   default String name() {
      return "";
   }
}
