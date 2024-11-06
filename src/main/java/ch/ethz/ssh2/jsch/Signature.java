package ch.ethz.ssh2.jsch;

public interface Signature {
   void init() throws Exception;

   void update(byte[] var1) throws Exception;

   boolean verify(byte[] var1) throws Exception;

   byte[] sign() throws Exception;
}
