package ch.ethz.ssh2.jsch;

abstract class DHXECKEM extends KeyExchange {
   private static final int SSH_MSG_KEX_ECDH_INIT = 30;

   private static final int SSH_MSG_KEX_ECDH_REPLY = 31;

   private int state;

   byte[] Q_C;

   byte[] V_S;

   byte[] V_C;

   byte[] I_S;

   byte[] I_C;

   byte[] e;

   private Buffer buf;

   private Packet packet;

   private KEM kem;

   private XDH xdh;

   protected String kem_name;

   protected String sha_name;

   protected String curve_name;

   protected int kem_pubkey_len;

   protected int kem_encap_len;

   protected int xec_key_len;

   public void init(byte[] V_S, byte[] V_C, byte[] I_S, byte[] I_C) throws Exception {
      this.V_S = V_S;
      this.V_C = V_C;
      this.I_S = I_S;
      this.I_C = I_C;
      try {
         Class<? extends HASH> c = Class.forName(Util.getConfig(this.sha_name)).asSubclass(HASH.class);
         this.sha = c.getDeclaredConstructor(new Class[0]).newInstance(new Object[0]);
         this.sha.init();
      } catch (Exception e) {
         throw new JSchException(e.toString(), e);
      }
      this.buf = new Buffer();
      this.packet = new Packet(this.buf);
      this.packet.reset();
      this.buf.checkFreeSize(5 + this.kem_pubkey_len + this.xec_key_len);
      this.buf.putByte((byte)30);
      try {
         Class<? extends KEM> k = Class.forName(Util.getConfig(this.kem_name)).asSubclass(KEM.class);
         this.kem = k.getDeclaredConstructor(new Class[0]).newInstance(new Object[0]);
         this.kem.init();
         Class<? extends XDH> c = Class.forName(Util.getConfig("xdh")).asSubclass(XDH.class);
         this.xdh = c.getDeclaredConstructor(new Class[0]).newInstance(new Object[0]);
         this.xdh.init(this.curve_name, this.xec_key_len);
         byte[] kem_public_key_C = this.kem.getPublicKey();
         byte[] xec_public_key_C = this.xdh.getQ();
         this.Q_C = new byte[this.kem_pubkey_len + this.xec_key_len];
         System.arraycopy(kem_public_key_C, 0, this.Q_C, 0, this.kem_pubkey_len);
         System.arraycopy(xec_public_key_C, 0, this.Q_C, this.kem_pubkey_len, this.xec_key_len);
         this.buf.putString(this.Q_C);
      } catch (Exception|NoClassDefFoundError e) {
         throw new JSchException(e.toString(), e);
      }
      if (V_S == null)
         return;
      this.state = 31;
   }

   public boolean next(Buffer _buf) throws Exception {
      int i;
      int j;
      byte[] Q_S;
      byte[] encapsulation;
      byte[] xec_public_key_S;
      byte[] tmp;
      byte[] sig_of_H;
      byte[] foo;
      String alg;
      boolean result;
      switch (this.state) {
         case 31:
            j = _buf.getInt();
            j = _buf.getByte();
            j = _buf.getByte();
            if (j != 31)
               return false;
            this.K_S = _buf.getString();
            Q_S = _buf.getString();
            if (Q_S.length != this.kem_encap_len + this.xec_key_len)
               return false;
            encapsulation = new byte[this.kem_encap_len];
            xec_public_key_S = new byte[this.xec_key_len];
            System.arraycopy(Q_S, 0, encapsulation, 0, this.kem_encap_len);
            System.arraycopy(Q_S, this.kem_encap_len, xec_public_key_S, 0, this.xec_key_len);
            if (!this.xdh.validate(xec_public_key_S))
               return false;
            tmp = null;
            try {
               tmp = this.kem.decapsulate(encapsulation);
               this.sha.update(tmp, 0, tmp.length);
            } finally {
               Util.bzero(tmp);
            }
            try {
               tmp = normalize(this.xdh.getSecret(xec_public_key_S));
               this.sha.update(tmp, 0, tmp.length);
            } finally {
               Util.bzero(tmp);
            }
            this.K = encodeAsString(this.sha.digest());
            sig_of_H = _buf.getString();
            this.buf.reset();
            this.buf.putString(this.V_C);
            this.buf.putString(this.V_S);
            this.buf.putString(this.I_C);
            this.buf.putString(this.I_S);
            this.buf.putString(this.K_S);
            this.buf.putString(this.Q_C);
            this.buf.putString(Q_S);
            foo = new byte[this.buf.getLength()];
            this.buf.getByte(foo);
            this.sha.update(foo, 0, foo.length);
            this.sha.update(this.K, 0, this.K.length);
            this.H = this.sha.digest();
            i = 0;
            j = 0;
            j = this.K_S[i++] << 24 & 0xFF000000 | this.K_S[i++] << 16 & 0xFF0000 |
                    this.K_S[i++] << 8 & 0xFF00 | this.K_S[i++] & 0xFF;
            alg = Util.byte2str(this.K_S, i, j);
            i += j;
            result = verify(alg, this.K_S, i, sig_of_H);
            this.state = 0;
            return result;
      }
      return false;
   }

   public int getState() {
      return this.state;
   }
}
