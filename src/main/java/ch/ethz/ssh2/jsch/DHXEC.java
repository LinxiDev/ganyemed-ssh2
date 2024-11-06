package ch.ethz.ssh2.jsch;

abstract class DHXEC extends KeyExchange {
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

   private XDH xdh;

   protected String sha_name;

   protected String curve_name;

   protected int key_len;

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
      this.buf.putByte((byte)30);
      try {
         Class<? extends XDH> c = Class.forName(Util.getConfig("xdh")).asSubclass(XDH.class);
         this.xdh = c.getDeclaredConstructor(new Class[0]).newInstance(new Object[0]);
         this.xdh.init(this.curve_name, this.key_len);
         this.Q_C = this.xdh.getQ();
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
            if (!this.xdh.validate(Q_S))
               return false;
            this.K = encodeAsMPInt(normalize(this.xdh.getSecret(Q_S)));
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
