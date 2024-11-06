package ch.ethz.ssh2.jsch;

import java.util.Arrays;

class KeyPairEd25519 extends KeyPairEdDSA {
   private static int keySize = 32;

   KeyPairEd25519() {
      this((byte[])null, (byte[])null);
   }

   KeyPairEd25519(byte[] pub_array, byte[] prv_array) {
      super(pub_array, prv_array);
   }

   public int getKeyType() {
      return 5;
   }

   public int getKeySize() {
      return keySize;
   }

   String getSshName() {
      return "ssh-ed25519";
   }

   String getJceName() {
      return "Ed25519";
   }

   static KeyPair fromSSHAgent(Buffer buf) throws Exception {
      byte[][] tmp = buf.getBytes(4, "invalid key format");
      byte[] pub_array = tmp[1];
      byte[] prv_array = Arrays.copyOf(tmp[2], keySize);
      KeyPairEd25519 kpair = new KeyPairEd25519(pub_array, prv_array);
      kpair.publicKeyComment = Util.byte2str(tmp[3]);
      kpair.vendor = 0;
      return kpair;
   }
}
