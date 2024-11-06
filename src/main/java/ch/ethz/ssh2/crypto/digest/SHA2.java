package ch.ethz.ssh2.crypto.digest;

import java.security.DigestException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class SHA2 implements Digest {
   private MessageDigest md = null;

   public SHA2(int keyLen) {
      try {
         this.md = MessageDigest.getInstance("SHA-" + keyLen);
      } catch (NoSuchAlgorithmException var3) {
         throw new RuntimeException(var3);
      }
   }

   public int getDigestLength() {
      return this.md.getDigestLength();
   }

   public void update(byte b) {
      this.md.update(b);
   }

   public void update(byte[] b) {
      this.md.update(b);
   }

   public void update(byte[] b, int off, int len) {
      this.md.update(b, off, len);
   }

   public void reset() {
      this.md.reset();
   }

   public void digest(byte[] out) {
      try {
         this.md.digest(out, 0, out.length);
      } catch (DigestException var3) {
         throw new RuntimeException(var3);
      }
   }

   public void digest(byte[] out, int off) {
      try {
         this.md.digest(out, off, out.length - off);
      } catch (DigestException var4) {
         throw new RuntimeException(var4);
      }
   }
}
