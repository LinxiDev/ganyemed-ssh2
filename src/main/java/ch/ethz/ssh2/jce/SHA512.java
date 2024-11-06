package ch.ethz.ssh2.jce;

import ch.ethz.ssh2.crypto.digest.HASH;
import java.security.MessageDigest;

public class SHA512 implements HASH {
   MessageDigest md;

   public int getBlockSize() {
      return 64;
   }

   public void init() throws Exception {
      this.md = MessageDigest.getInstance("SHA-512");
   }

   public void update(byte[] foo, int start, int len) throws Exception {
      this.md.update(foo, start, len);
   }

   public byte[] digest() throws Exception {
      return this.md.digest();
   }

   public String name() {
      return "SHA512";
   }
}
