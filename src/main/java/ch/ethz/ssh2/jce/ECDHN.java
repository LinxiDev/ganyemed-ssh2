package ch.ethz.ssh2.jce;

import ch.ethz.ssh2.jsch.ECDH;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import javax.crypto.KeyAgreement;

public class ECDHN implements ECDH {
   byte[] Q_array;
   ECPublicKey publicKey;
   private KeyAgreement myKeyAgree;
   private static BigInteger two;
   private static BigInteger three;

   static {
      two = BigInteger.ONE.add(BigInteger.ONE);
      three = two.add(BigInteger.ONE);
   }

   public void init(int size) throws Exception {
      this.myKeyAgree = KeyAgreement.getInstance("ECDH");
      KeyPairGenECDSA kpair = new KeyPairGenECDSA();
      kpair.init(size);
      this.publicKey = kpair.getPublicKey();
      byte[] r = kpair.getR();
      byte[] s = kpair.getS();
      this.Q_array = this.toPoint(r, s);
      this.myKeyAgree.init(kpair.getPrivateKey());
   }

   public byte[] getQ() throws Exception {
      return this.Q_array;
   }

   public byte[] getSecret(byte[] r, byte[] s) throws Exception {
      KeyFactory kf = KeyFactory.getInstance("EC");
      ECPoint w = new ECPoint(new BigInteger(1, r), new BigInteger(1, s));
      ECPublicKeySpec spec = new ECPublicKeySpec(w, this.publicKey.getParams());
      PublicKey theirPublicKey = kf.generatePublic(spec);
      this.myKeyAgree.doPhase(theirPublicKey, true);
      return this.myKeyAgree.generateSecret();
   }

   public boolean validate(byte[] r, byte[] s) throws Exception {
      BigInteger x = new BigInteger(1, r);
      BigInteger y = new BigInteger(1, s);
      ECPoint w = new ECPoint(x, y);
      if (w.equals(ECPoint.POINT_INFINITY)) {
         return false;
      } else {
         ECParameterSpec params = this.publicKey.getParams();
         EllipticCurve curve = params.getCurve();
         BigInteger p = ((ECFieldFp)curve.getField()).getP();
         BigInteger p_sub1 = p.subtract(BigInteger.ONE);
         if (x.compareTo(p_sub1) <= 0 && y.compareTo(p_sub1) <= 0) {
            BigInteger tmp = x.multiply(curve.getA()).add(curve.getB()).add(x.modPow(three, p)).mod(p);
            BigInteger y_2 = y.modPow(two, p);
            return y_2.equals(tmp);
         } else {
            return false;
         }
      }
   }

   private byte[] toPoint(byte[] r_array, byte[] s_array) {
      byte[] tmp = new byte[1 + r_array.length + s_array.length];
      tmp[0] = 4;
      System.arraycopy(r_array, 0, tmp, 1, r_array.length);
      System.arraycopy(s_array, 0, tmp, 1 + r_array.length, s_array.length);
      return tmp;
   }

   private byte[] insert0(byte[] buf) {
      if ((buf[0] & 128) == 0) {
         return buf;
      } else {
         byte[] tmp = new byte[buf.length + 1];
         System.arraycopy(buf, 0, tmp, 1, buf.length);
         Util.bzero(buf);
         return tmp;
      }
   }

   private byte[] chop0(byte[] buf) {
      if (buf[0] != 0) {
         return buf;
      } else {
         byte[] tmp = new byte[buf.length - 1];
         System.arraycopy(buf, 1, tmp, 0, tmp.length);
         Util.bzero(buf);
         return tmp;
      }
   }
}
