package ch.ethz.ssh2.jsch;

public interface SignatureRSA extends Signature {
   void setPubKey(byte[] var1, byte[] var2) throws Exception;

   void setPrvKey(byte[] var1, byte[] var2) throws Exception;
}