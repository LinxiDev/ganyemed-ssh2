package ch.ethz.ssh2.jsch;

abstract class DH25519 extends DHXEC {
   public DH25519() {
      this.sha_name = "sha-256";
      this.curve_name = "X25519";
      this.key_len = 32;
   }
}
