package ch.ethz.ssh2.jsch;

public interface KeyPairGenDSA {
   void init(int var1) throws Exception;

   byte[] getX();

   byte[] getY();

   byte[] getP();

   byte[] getQ();

   byte[] getG();
}
