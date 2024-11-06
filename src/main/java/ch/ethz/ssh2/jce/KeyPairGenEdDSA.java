package ch.ethz.ssh2.jce;

public class KeyPairGenEdDSA implements ch.ethz.ssh2.jsch.KeyPairGenEdDSA {
   public KeyPairGenEdDSA() {
      throw new UnsupportedOperationException("KeyPairGenEdDSA requires Java15+.");
   }

   public void init(String name, int keylen) throws Exception {
      throw new UnsupportedOperationException("KeyPairGenEdDSA requires Java15+.");
   }

   public byte[] getPrv() {
      throw new UnsupportedOperationException("KeyPairGenEdDSA requires Java15+.");
   }

   public byte[] getPub() {
      throw new UnsupportedOperationException("KeyPairGenEdDSA requires Java15+.");
   }
}
