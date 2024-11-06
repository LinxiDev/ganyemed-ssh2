package ch.ethz.ssh2.jsch;

public interface XDH {
   void init(String var1, int var2) throws Exception;

   byte[] getSecret(byte[] var1) throws Exception;

   byte[] getQ() throws Exception;

   boolean validate(byte[] var1) throws Exception;
}
