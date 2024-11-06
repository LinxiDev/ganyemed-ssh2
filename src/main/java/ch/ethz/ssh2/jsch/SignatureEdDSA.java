package ch.ethz.ssh2.jsch;

public interface SignatureEdDSA extends Signature {
   void setPubKey(byte[] var1) throws Exception;

   void setPrvKey(byte[] var1) throws Exception;
}
