package ch.ethz.ssh2.jce;

public class XDH implements ch.ethz.ssh2.jsch.XDH {
   public XDH() {
      throw new UnsupportedOperationException("XDH requires Java11+.");
   }

   public void init(String name, int keylen) throws Exception {
      throw new UnsupportedOperationException("XDH requires Java11+.");
   }

   public byte[] getQ() throws Exception {
      throw new UnsupportedOperationException("XDH requires Java11+.");
   }

   public byte[] getSecret(byte[] Q) throws Exception {
      throw new UnsupportedOperationException("XDH requires Java11+.");
   }

   public boolean validate(byte[] u) throws Exception {
      throw new UnsupportedOperationException("XDH requires Java11+.");
   }
}
