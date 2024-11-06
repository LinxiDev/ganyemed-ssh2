package ch.ethz.ssh2.jce;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/** @deprecated */
@Deprecated
public class PBKDF implements ch.ethz.ssh2.jsch.PBKDF {
   public byte[] getKey(byte[] _pass, byte[] salt, int iterations, int size) {
      char[] pass = new char[_pass.length];

      for(int i = 0; i < _pass.length; ++i) {
         pass[i] = (char)(_pass[i] & 255);
      }

      try {
         PBEKeySpec spec = new PBEKeySpec(pass, salt, iterations, size * 8);
         SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
         byte[] key = skf.generateSecret(spec).getEncoded();
         return key;
      } catch (InvalidKeySpecException var9) {
      } catch (NoSuchAlgorithmException var10) {
      }

      return null;
   }
}
