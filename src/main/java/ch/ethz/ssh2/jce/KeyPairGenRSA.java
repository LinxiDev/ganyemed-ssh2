package ch.ethz.ssh2.jce;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class KeyPairGenRSA implements ch.ethz.ssh2.jsch.KeyPairGenRSA {
   byte[] d;
   byte[] e;
   byte[] n;
   byte[] c;
   byte[] ep;
   byte[] eq;
   byte[] p;
   byte[] q;

   public void init(int key_size) throws Exception {
      KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
      keyGen.initialize(key_size, new SecureRandom());
      KeyPair pair = keyGen.generateKeyPair();
      PublicKey pubKey = pair.getPublic();
      PrivateKey prvKey = pair.getPrivate();
      this.d = ((RSAPrivateKey)prvKey).getPrivateExponent().toByteArray();
      this.e = ((RSAPublicKey)pubKey).getPublicExponent().toByteArray();
      this.n = ((RSAPrivateKey)prvKey).getModulus().toByteArray();
      this.c = ((RSAPrivateCrtKey)prvKey).getCrtCoefficient().toByteArray();
      this.ep = ((RSAPrivateCrtKey)prvKey).getPrimeExponentP().toByteArray();
      this.eq = ((RSAPrivateCrtKey)prvKey).getPrimeExponentQ().toByteArray();
      this.p = ((RSAPrivateCrtKey)prvKey).getPrimeP().toByteArray();
      this.q = ((RSAPrivateCrtKey)prvKey).getPrimeQ().toByteArray();
   }

   public byte[] getD() {
      return this.d;
   }

   public byte[] getE() {
      return this.e;
   }

   public byte[] getN() {
      return this.n;
   }

   public byte[] getC() {
      return this.c;
   }

   public byte[] getEP() {
      return this.ep;
   }

   public byte[] getEQ() {
      return this.eq;
   }

   public byte[] getP() {
      return this.p;
   }

   public byte[] getQ() {
      return this.q;
   }
}
