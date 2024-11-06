package ch.ethz.ssh2.jsch;

public interface Identity {
   boolean setPassphrase(byte[] var1) throws JSchException;

   byte[] getPublicKeyBlob();

   byte[] getSignature(byte[] var1);

   default byte[] getSignature(byte[] data, String alg) {
      return this.getSignature(data);
   }

   /** @deprecated */
   @Deprecated
   default boolean decrypt() {
      throw new UnsupportedOperationException("not implemented");
   }

   String getAlgName();

   String getName();

   boolean isEncrypted();

   void clear();
}
