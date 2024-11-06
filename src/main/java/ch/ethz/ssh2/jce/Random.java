package ch.ethz.ssh2.jce;

import java.security.SecureRandom;

public class Random implements ch.ethz.ssh2.jsch.Random {
   private byte[] tmp = new byte[16];
   private SecureRandom random = null;

   public Random() {
      this.random = new SecureRandom();
   }

   public void fill(byte[] foo, int start, int len) {
      if (len > this.tmp.length) {
         this.tmp = new byte[len];
      }

      this.random.nextBytes(this.tmp);
      System.arraycopy(this.tmp, 0, foo, start, len);
   }
}
