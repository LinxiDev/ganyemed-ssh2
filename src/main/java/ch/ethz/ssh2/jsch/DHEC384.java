package ch.ethz.ssh2.jsch;

class DHEC384 extends DHECN {
   public DHEC384() {
      this.sha_name = "sha-384";
      this.key_size = 384;
   }
}
