package ch.ethz.ssh2.jsch;

class DHEC256 extends DHECN {
   public DHEC256() {
      this.sha_name = "sha-256";
      this.key_size = 256;
   }
}
