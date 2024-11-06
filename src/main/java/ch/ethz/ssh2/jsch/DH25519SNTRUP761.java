package ch.ethz.ssh2.jsch;

class DH25519SNTRUP761 extends DHXECKEM {
   public DH25519SNTRUP761() {
      this.kem_name = "sntrup761";
      this.sha_name = "sha-512";
      this.curve_name = "X25519";
      this.kem_pubkey_len = 1158;
      this.kem_encap_len = 1039;
      this.xec_key_len = 32;
   }
}
