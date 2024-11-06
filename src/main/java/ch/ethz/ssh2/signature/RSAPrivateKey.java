package ch.ethz.ssh2.signature;

import java.math.BigInteger;
import java.security.SecureRandom;

public class RSAPrivateKey {
   private BigInteger d;
   private BigInteger e;
   private BigInteger n;

   public RSAPrivateKey(BigInteger d, BigInteger e, BigInteger n) {
      this.d = d;
      this.e = e;
      this.n = n;
   }

   public BigInteger getD() {
      return this.d;
   }

   public BigInteger getE() {
      return this.e;
   }

   public BigInteger getN() {
      return this.n;
   }

   public RSAPublicKey getPublicKey() {
      return new RSAPublicKey(this.e, this.n);
   }

   public static RSAPrivateKey generateKey(int numbits) {
      return generateKey(new SecureRandom(), numbits);
   }

   public static RSAPrivateKey generateKey(SecureRandom rnd, int numbits) {
      BigInteger p = BigInteger.probablePrime(numbits / 2, rnd);
      BigInteger q = BigInteger.probablePrime(numbits / 2, rnd);
      BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
      BigInteger n = p.multiply(q);
      BigInteger e = new BigInteger("65537");
      BigInteger d = e.modInverse(phi);
      return new RSAPrivateKey(d, e, n);
   }
}
