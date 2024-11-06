package ch.ethz.ssh2.jce;

import ch.ethz.ssh2.jsch.Buffer;
import ch.ethz.ssh2.jsch.SignatureECDSA;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.*;

abstract class SignatureECDSAN implements SignatureECDSA {
   Signature signature;

   KeyFactory keyFactory;

   abstract String getName();

   public void init() throws Exception {
      String name = getName();
      String foo = "SHA256withECDSA";
      if (name.equals("ecdsa-sha2-nistp384")) {
         foo = "SHA384withECDSA";
      } else if (name.equals("ecdsa-sha2-nistp521")) {
         foo = "SHA512withECDSA";
      }
      this.signature = Signature.getInstance(foo);
      this.keyFactory = KeyFactory.getInstance("EC");
   }

   public void setPubKey(byte[] r, byte[] s) throws Exception {
      r = insert0(r);
      s = insert0(s);
      String name = "secp256r1";
      if (r.length >= 64) {
         name = "secp521r1";
      } else if (r.length >= 48) {
         name = "secp384r1";
      }
      AlgorithmParameters param = AlgorithmParameters.getInstance("EC");
      param.init(new ECGenParameterSpec(name));
      ECParameterSpec ecparam = param.<ECParameterSpec>getParameterSpec(ECParameterSpec.class);
      ECPoint w = new ECPoint(new BigInteger(1, r), new BigInteger(1, s));
      PublicKey pubKey = this.keyFactory.generatePublic(new ECPublicKeySpec(w, ecparam));
      this.signature.initVerify(pubKey);
   }

   public void setPrvKey(byte[] d) throws Exception {
      d = insert0(d);
      String name = "secp256r1";
      if (d.length >= 64) {
         name = "secp521r1";
      } else if (d.length >= 48) {
         name = "secp384r1";
      }
      AlgorithmParameters param = AlgorithmParameters.getInstance("EC");
      param.init(new ECGenParameterSpec(name));
      ECParameterSpec ecparam = param.<ECParameterSpec>getParameterSpec(ECParameterSpec.class);
      BigInteger _d = new BigInteger(1, d);
      PrivateKey prvKey = this.keyFactory.generatePrivate(new ECPrivateKeySpec(_d, ecparam));
      this.signature.initSign(prvKey);
   }

   public byte[] sign() throws Exception {
      byte[] sig = this.signature.sign();
      if (sig[0] == 48 && (
              sig[1] + 2 == sig.length || ((
                      sig[1] & 0x80) != 0 && (sig[2] & 0xFF) + 3 == sig.length))) {
         int index = 3;
         if ((sig[1] & 0x80) != 0 && (sig[2] & 0xFF) + 3 == sig.length)
            index = 4;
         byte[] r = new byte[sig[index]];
         byte[] s = new byte[sig[index + 2 + sig[index]]];
         System.arraycopy(sig, index + 1, r, 0, r.length);
         System.arraycopy(sig, index + 3 + sig[index], s, 0, s.length);
         r = chop0(r);
         s = chop0(s);
         Buffer buf = new Buffer();
         buf.putMPInt(r);
         buf.putMPInt(s);
         sig = new byte[buf.getLength()];
         buf.setOffSet(0);
         buf.getByte(sig);
      }
      return sig;
   }

   public void update(byte[] foo) throws Exception {
      this.signature.update(foo);
   }

   public boolean verify(byte[] sig) throws Exception {
      if (sig[0] != 48 || (
              sig[1] + 2 != sig.length && ((
                      sig[1] & 0x80) == 0 || (sig[2] & 0xFF) + 3 != sig.length))) {
         Buffer b = new Buffer(sig);
         b.getString();
         b.getInt();
         byte[] r = b.getMPInt();
         byte[] s = b.getMPInt();
         r = trimLeadingZeros(insert0(r));
         s = trimLeadingZeros(insert0(s));
         byte[] asn1 = null;
         if (r.length < 64) {
            asn1 = new byte[6 + r.length + s.length];
            asn1[0] = 48;
            asn1[1] = (byte)(4 + r.length + s.length);
            asn1[2] = 2;
            asn1[3] = (byte)r.length;
            System.arraycopy(r, 0, asn1, 4, r.length);
            asn1[r.length + 4] = 2;
            asn1[r.length + 5] = (byte)s.length;
            System.arraycopy(s, 0, asn1, 6 + r.length, s.length);
         } else {
            asn1 = new byte[6 + r.length + s.length + 1];
            asn1[0] = 48;
            asn1[1] = -127;
            asn1[2] = (byte)(4 + r.length + s.length);
            asn1[3] = 2;
            asn1[4] = (byte)r.length;
            System.arraycopy(r, 0, asn1, 5, r.length);
            asn1[r.length + 5] = 2;
            asn1[r.length + 6] = (byte)s.length;
            System.arraycopy(s, 0, asn1, 7 + r.length, s.length);
         }
         sig = asn1;
      }
      return this.signature.verify(sig);
   }

   private static byte[] insert0(byte[] buf) {
      if ((buf[0] & 0x80) == 0)
         return buf;
      byte[] tmp = new byte[buf.length + 1];
      System.arraycopy(buf, 0, tmp, 1, buf.length);
      Util.bzero(buf);
      return tmp;
   }

   private static byte[] chop0(byte[] buf) {
      if (buf[0] != 0)
         return buf;
      byte[] tmp = new byte[buf.length - 1];
      System.arraycopy(buf, 1, tmp, 0, tmp.length);
      Util.bzero(buf);
      return tmp;
   }

   private static byte[] trimLeadingZeros(byte[] buf) {
      if (buf.length < 2)
         return buf;
      int i = 0;
      while (i < buf.length - 1 &&
              buf[i] == 0 && (buf[i + 1] & 0x80) == 0)
         i++;
      if (i == 0)
         return buf;
      byte[] tmp = new byte[buf.length - i];
      System.arraycopy(buf, i, tmp, 0, tmp.length);
      Util.bzero(buf);
      return tmp;
   }
}
