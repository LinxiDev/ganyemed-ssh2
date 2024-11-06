package ch.ethz.ssh2.jsch;

public interface KEM {
   void init() throws Exception;

   byte[] getPublicKey() throws Exception;

   byte[] decapsulate(byte[] var1) throws Exception;
}
