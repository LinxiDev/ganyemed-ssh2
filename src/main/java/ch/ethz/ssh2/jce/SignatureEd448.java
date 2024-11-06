package ch.ethz.ssh2.jce;

import ch.ethz.ssh2.jsch.SignatureEdDSA;

public class SignatureEd448 implements SignatureEdDSA {
   public SignatureEd448() {
      throw new UnsupportedOperationException("SignatureEd448 requires Java15+.");
   }

   public void init() throws Exception {
      throw new UnsupportedOperationException("SignatureEd448 requires Java15+.");
   }

   public void setPubKey(byte[] y_arr) throws Exception {
      throw new UnsupportedOperationException("SignatureEd448 requires Java15+.");
   }

   public void setPrvKey(byte[] bytes) throws Exception {
      throw new UnsupportedOperationException("SignatureEd448 requires Java15+.");
   }

   public byte[] sign() throws Exception {
      throw new UnsupportedOperationException("SignatureEd448 requires Java15+.");
   }

   public void update(byte[] foo) throws Exception {
      throw new UnsupportedOperationException("SignatureEd448 requires Java15+.");
   }

   public boolean verify(byte[] sig) throws Exception {
      throw new UnsupportedOperationException("SignatureEd448 requires Java15+.");
   }
}
