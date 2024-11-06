package ch.ethz.ssh2.jce;

import ch.ethz.ssh2.jsch.Buffer;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;

public class SignatureDSA implements ch.ethz.ssh2.jsch.SignatureDSA {
   Signature signature;

   KeyFactory keyFactory;

   public void init() throws Exception {
      this.signature = Signature.getInstance("SHA1withDSA");
      this.keyFactory = KeyFactory.getInstance("DSA");
   }

   public void setPubKey(byte[] y, byte[] p, byte[] q, byte[] g) throws Exception {
      DSAPublicKeySpec dsaPubKeySpec = new DSAPublicKeySpec(new BigInteger(y), new BigInteger(p),
              new BigInteger(q), new BigInteger(g));
      PublicKey pubKey = this.keyFactory.generatePublic(dsaPubKeySpec);
      this.signature.initVerify(pubKey);
   }

   public void setPrvKey(byte[] x, byte[] p, byte[] q, byte[] g) throws Exception {
      DSAPrivateKeySpec dsaPrivKeySpec = new DSAPrivateKeySpec(new BigInteger(x), new BigInteger(p),
              new BigInteger(q), new BigInteger(g));
      PrivateKey prvKey = this.keyFactory.generatePrivate(dsaPrivKeySpec);
      this.signature.initSign(prvKey);
   }

   public byte[] sign() throws Exception {
      byte[] sig = this.signature.sign();
      int len = 0;
      int index = 3;
      len = sig[index++] & 0xFF;
      byte[] r = new byte[len];
      System.arraycopy(sig, index, r, 0, r.length);
      index = index + len + 1;
      len = sig[index++] & 0xFF;
      byte[] s = new byte[len];
      System.arraycopy(sig, index, s, 0, s.length);
      byte[] result = new byte[40];
      System.arraycopy(r, (r.length > 20) ? 1 : 0, result, (r.length > 20) ? 0 : (20 - r.length),
              (r.length > 20) ? 20 : r.length);
      System.arraycopy(s, (s.length > 20) ? 1 : 0, result, (s.length > 20) ? 20 : (40 - s.length),
              (s.length > 20) ? 20 : s.length);
      return result;
   }

   public void update(byte[] foo) throws Exception {
      this.signature.update(foo);
   }

   public boolean verify(byte[] sig) throws Exception {
      int i = 0;
      int j = 0;
      Buffer buf = new Buffer(sig);
      if ((new String(buf.getString(), StandardCharsets.UTF_8)).equals("ssh-dss")) {
         j = buf.getInt();
         i = buf.getOffSet();
         byte[] arrayOfByte = new byte[j];
         System.arraycopy(sig, i, arrayOfByte, 0, j);
         sig = arrayOfByte;
      }
      byte[] _frst = new byte[20];
      System.arraycopy(sig, 0, _frst, 0, 20);
      _frst = normalize(_frst);
      byte[] _scnd = new byte[20];
      System.arraycopy(sig, 20, _scnd, 0, 20);
      _scnd = normalize(_scnd);
      int frst = ((_frst[0] & 0x80) != 0) ? 1 : 0;
      int scnd = ((_scnd[0] & 0x80) != 0) ? 1 : 0;
      int length = _frst.length + _scnd.length + 6 + frst + scnd;
      byte[] tmp = new byte[length];
      tmp[0] = 48;
      tmp[1] = (byte)(_frst.length + _scnd.length + 4);
      tmp[1] = (byte)(tmp[1] + (byte)frst);
      tmp[1] = (byte)(tmp[1] + (byte)scnd);
      tmp[2] = 2;
      tmp[3] = (byte)_frst.length;
      tmp[3] = (byte)(tmp[3] + (byte)frst);
      System.arraycopy(_frst, 0, tmp, 4 + frst, _frst.length);
      tmp[4 + tmp[3]] = 2;
      tmp[5 + tmp[3]] = (byte)_scnd.length;
      tmp[5 + tmp[3]] = (byte)(tmp[5 + tmp[3]] + (byte)scnd);
      System.arraycopy(_scnd, 0, tmp, 6 + tmp[3] + scnd, _scnd.length);
      sig = tmp;
      return this.signature.verify(sig);
   }

   protected byte[] normalize(byte[] secret) {
      if (secret.length > 1 && secret[0] == 0 && (secret[1] & 0x80) == 0) {
         byte[] tmp = new byte[secret.length - 1];
         System.arraycopy(secret, 1, tmp, 0, tmp.length);
         return normalize(tmp);
      }
      return secret;
   }
}
