package ch.ethz.ssh2.jce;

import ch.ethz.ssh2.jsch.Buffer;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

abstract class SignatureRSAN implements ch.ethz.ssh2.jsch.SignatureRSA {
   Signature signature;

   KeyFactory keyFactory;

   abstract String getName();

   public void init() throws Exception {
      String name = getName();
      String foo = "SHA1withRSA";
      if (name.equals("rsa-sha2-256") || name.equals("ssh-rsa-sha256@ssh.com")) {
         foo = "SHA256withRSA";
      } else if (name.equals("rsa-sha2-512") || name.equals("ssh-rsa-sha512@ssh.com")) {
         foo = "SHA512withRSA";
      } else if (name.equals("ssh-rsa-sha384@ssh.com")) {
         foo = "SHA384withRSA";
      } else if (name.equals("ssh-rsa-sha224@ssh.com")) {
         foo = "SHA224withRSA";
      }
      this.signature = Signature.getInstance(foo);
      this.keyFactory = KeyFactory.getInstance("RSA");
   }

   public void setPubKey(byte[] e, byte[] n) throws Exception {
      RSAPublicKeySpec rsaPubKeySpec = new RSAPublicKeySpec(new BigInteger(n), new BigInteger(e));
      PublicKey pubKey = this.keyFactory.generatePublic(rsaPubKeySpec);
      this.signature.initVerify(pubKey);
   }

   public void setPrvKey(byte[] d, byte[] n) throws Exception {
      RSAPrivateKeySpec rsaPrivKeySpec = new RSAPrivateKeySpec(new BigInteger(n), new BigInteger(d));
      PrivateKey prvKey = this.keyFactory.generatePrivate(rsaPrivKeySpec);
      this.signature.initSign(prvKey);
   }

   public byte[] sign() throws Exception {
      byte[] sig = this.signature.sign();
      return sig;
   }

   public void update(byte[] foo) throws Exception {
      this.signature.update(foo);
   }

   public boolean verify(byte[] sig) throws Exception {
      int i = 0;
      int j = 0;
      Buffer buf = new Buffer(sig);
      String foo = new String(buf.getString(), StandardCharsets.UTF_8);
      if (foo.equals("ssh-rsa") || foo.equals("rsa-sha2-256") || foo.equals("rsa-sha2-512") ||
              foo.equals("ssh-rsa-sha224@ssh.com") || foo.equals("ssh-rsa-sha256@ssh.com") ||
              foo.equals("ssh-rsa-sha384@ssh.com") || foo.equals("ssh-rsa-sha512@ssh.com")) {
         if (!foo.equals(getName()))
            return false;
         j = buf.getInt();
         i = buf.getOffSet();
         byte[] tmp = new byte[j];
         System.arraycopy(sig, i, tmp, 0, j);
         sig = tmp;
      }
      return this.signature.verify(sig);
   }
}
