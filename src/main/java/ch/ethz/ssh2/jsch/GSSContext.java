package ch.ethz.ssh2.jsch;

public interface GSSContext {
   void create(String var1, String var2) throws JSchException;

   boolean isEstablished();

   byte[] init(byte[] var1, int var2, int var3) throws JSchException;

   byte[] getMIC(byte[] var1, int var2, int var3);

   void dispose();
}
