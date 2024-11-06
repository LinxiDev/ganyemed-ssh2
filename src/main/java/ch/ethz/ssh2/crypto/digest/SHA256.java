package ch.ethz.ssh2.crypto.digest;

import java.security.MessageDigest;

public class SHA256 implements HASH {
   MessageDigest md;

   public int getBlockSize() {
      return 32;
   }

   public void init() throws Exception {
      this.md = MessageDigest.getInstance("SHA-256");
   }

   public void update(byte[] foo, int start, int len) throws Exception {
      this.md.update(foo, start, len);
   }

   public byte[] digest() throws Exception {
      return this.md.digest();
   }

   public String name() {
      return "SHA256";
   }
}
