package ch.ethz.ssh2.jsch;

import java.util.Arrays;

class KeyPairEd448 extends KeyPairEdDSA {
   private static int keySize = 57;

   KeyPairEd448() {
      this((byte[])null, (byte[])null);
   }

   KeyPairEd448(byte[] pub_array, byte[] prv_array) {
      super(pub_array, prv_array);
   }

   public int getKeyType() {
      return 6;
   }

   public int getKeySize() {
      return keySize;
   }

   String getSshName() {
      return "ssh-ed448";
   }

   String getJceName() {
      return "Ed448";
   }

   static KeyPair fromSSHAgent(Buffer buf) throws Exception {
      byte[][] tmp = buf.getBytes(4, "invalid key format");
      byte[] pub_array = tmp[1];
      byte[] prv_array = Arrays.copyOf(tmp[2], keySize);
      KeyPairEd448 kpair = new KeyPairEd448(pub_array, prv_array);
      kpair.publicKeyComment = Util.byte2str(tmp[3]);
      kpair.vendor = 0;
      return kpair;
   }
}
