package ch.ethz.ssh2.jce;

import ch.ethz.ssh2.crypto.digest.HASH;
import java.security.MessageDigest;

public class MD5 implements HASH {
   MessageDigest md;

   public int getBlockSize() {
      return 16;
   }

   public void init() throws Exception {
      this.md = MessageDigest.getInstance("MD5");
   }

   public void update(byte[] foo, int start, int len) throws Exception {
      this.md.update(foo, start, len);
   }

   public byte[] digest() throws Exception {
      return this.md.digest();
   }

   public String name() {
      return "MD5";
   }
}
