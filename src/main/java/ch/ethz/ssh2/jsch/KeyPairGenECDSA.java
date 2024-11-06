package ch.ethz.ssh2.jsch;

public interface KeyPairGenECDSA {
   void init(int var1) throws Exception;

   byte[] getD();

   byte[] getR();

   byte[] getS();
}
