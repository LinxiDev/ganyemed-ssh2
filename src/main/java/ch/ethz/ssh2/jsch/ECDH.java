package ch.ethz.ssh2.jsch;

public interface ECDH {
   void init(int var1) throws Exception;

   byte[] getSecret(byte[] var1, byte[] var2) throws Exception;

   byte[] getQ() throws Exception;

   boolean validate(byte[] var1, byte[] var2) throws Exception;
}
