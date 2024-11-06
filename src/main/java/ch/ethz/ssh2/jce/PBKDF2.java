package ch.ethz.ssh2.jce;

import java.security.spec.InvalidKeySpecException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

abstract class PBKDF2 implements ch.ethz.ssh2.jsch.PBKDF2 {
   private SecretKeyFactory skf;
   private byte[] salt;
   private int iterations;

   abstract String getName();

   public void init(byte[] salt, int iterations) throws Exception {
      this.skf = SecretKeyFactory.getInstance(this.getName());
      this.salt = salt;
      this.iterations = iterations;
   }

   public byte[] getKey(byte[] _pass, int size) {
      char[] pass = new char[_pass.length];

      for(int i = 0; i < _pass.length; ++i) {
         pass[i] = (char)(_pass[i] & 255);
      }

      try {
         PBEKeySpec spec = new PBEKeySpec(pass, this.salt, this.iterations, size * 8);
         byte[] key = this.skf.generateSecret(spec).getEncoded();
         return key;
      } catch (InvalidKeySpecException var6) {
         return null;
      }
   }
}
