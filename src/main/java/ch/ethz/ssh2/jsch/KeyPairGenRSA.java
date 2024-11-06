package ch.ethz.ssh2.jsch;

public interface KeyPairGenRSA {
   void init(int var1) throws Exception;

   byte[] getD();

   byte[] getE();

   byte[] getN();

   byte[] getC();

   byte[] getEP();

   byte[] getEQ();

   byte[] getP();

   byte[] getQ();
}
