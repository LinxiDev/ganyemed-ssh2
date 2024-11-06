package ch.ethz.ssh2.jsch;

public interface SignatureDSA extends Signature {
   void setPubKey(byte[] var1, byte[] var2, byte[] var3, byte[] var4) throws Exception;

   void setPrvKey(byte[] var1, byte[] var2, byte[] var3, byte[] var4) throws Exception;
}
