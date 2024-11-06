package ch.ethz.ssh2.jce;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.DSAKey;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;

public class KeyPairGenDSA implements ch.ethz.ssh2.jsch.KeyPairGenDSA {
   byte[] x;
   byte[] y;
   byte[] p;
   byte[] q;
   byte[] g;

   public void init(int key_size) throws Exception {
      KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
      keyGen.initialize(key_size, new SecureRandom());
      KeyPair pair = keyGen.generateKeyPair();
      PublicKey pubKey = pair.getPublic();
      PrivateKey prvKey = pair.getPrivate();
      this.x = ((DSAPrivateKey)prvKey).getX().toByteArray();
      this.y = ((DSAPublicKey)pubKey).getY().toByteArray();
      DSAParams params = ((DSAKey)prvKey).getParams();
      this.p = params.getP().toByteArray();
      this.q = params.getQ().toByteArray();
      this.g = params.getG().toByteArray();
   }

   public byte[] getX() {
      return this.x;
   }

   public byte[] getY() {
      return this.y;
   }

   public byte[] getP() {
      return this.p;
   }

   public byte[] getQ() {
      return this.q;
   }

   public byte[] getG() {
      return this.g;
   }
}
