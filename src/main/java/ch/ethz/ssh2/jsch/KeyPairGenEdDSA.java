package ch.ethz.ssh2.jsch;

public interface KeyPairGenEdDSA {
   void init(String var1, int var2) throws Exception;

   byte[] getPub();

   byte[] getPrv();

   default void init(String name, byte[] prv) throws Exception {
      throw new UnsupportedOperationException();
   }
}
