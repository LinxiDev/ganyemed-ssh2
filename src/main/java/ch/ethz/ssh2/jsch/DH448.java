package ch.ethz.ssh2.jsch;

class DH448 extends DHXEC {
   public DH448() {
      this.sha_name = "sha-512";
      this.curve_name = "X448";
      this.key_len = 56;
   }
}
