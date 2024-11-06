package ch.ethz.ssh2.jce;

public interface DH {
   void init() throws Exception;

   void setP(byte[] var1);

   void setG(byte[] var1);

   byte[] getE() throws Exception;

   void setF(byte[] var1);

   byte[] getK() throws Exception;

   void checkRange() throws Exception;
}
