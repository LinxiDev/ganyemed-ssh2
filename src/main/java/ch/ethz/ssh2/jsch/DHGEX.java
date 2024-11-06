package ch.ethz.ssh2.jsch;

import java.math.BigInteger;

abstract class DHGEX extends KeyExchange {
   private static final int SSH_MSG_KEX_DH_GEX_GROUP = 31;

   private static final int SSH_MSG_KEX_DH_GEX_INIT = 32;

   private static final int SSH_MSG_KEX_DH_GEX_REPLY = 33;

   private static final int SSH_MSG_KEX_DH_GEX_REQUEST = 34;

   int min;

   int preferred;

   int max;

   private int state;

   DH dh;

   byte[] V_S;

   byte[] V_C;

   byte[] I_S;

   byte[] I_C;

   private Buffer buf;

   private Packet packet;

   private byte[] p;

   private byte[] g;

   private byte[] e;

   protected String hash;

   public void init(byte[] V_S, byte[] V_C, byte[] I_S, byte[] I_C) throws Exception {
      this.V_S = V_S;
      this.V_C = V_C;
      this.I_S = I_S;
      this.I_C = I_C;
      try {
         Class<? extends HASH> c = Class.forName(Util.getConfig(this.hash)).asSubclass(HASH.class);
         this.sha = c.getDeclaredConstructor(new Class[0]).newInstance(new Object[0]);
         this.sha.init();
      } catch (Exception e) {
         throw new JSchException(e.toString(), e);
      }
      this.buf = new Buffer();
      this.packet = new Packet(this.buf);
      try {
         Class<? extends DH> c = Class.forName(Util.getConfig("dh")).asSubclass(DH.class);
         this.min = Integer.parseInt(Util.getConfig("dhgex_min"));
         this.max = Integer.parseInt(Util.getConfig("dhgex_max"));
         this.preferred = Integer.parseInt(Util.getConfig("dhgex_preferred"));
         if (this.min <= 0 || this.max <= 0 || this.preferred <= 0 || this.preferred < this.min || this.preferred > this.max)
            throw new JSchException(
                    "Invalid DHGEX sizes: min=" + this.min + " max=" + this.max + " preferred=" + this.preferred);
         this.dh = c.getDeclaredConstructor(new Class[0]).newInstance(new Object[0]);
         this.dh.init();
      } catch (Exception e) {
         throw new JSchException(e.toString(), e);
      }
      this.packet.reset();
      this.buf.putByte((byte)34);
      this.buf.putInt(this.min);
      this.buf.putInt(this.preferred);
      this.buf.putInt(this.max);
      this.state = 31;
   }

   public boolean next(Buffer _buf) throws Exception {
      int i;
      int j;
      int bits;
      byte[] f;
      byte[] sig_of_H;
      byte[] foo;
      String alg;
      boolean result;
      switch (this.state) {
         case 31:
            _buf.getInt();
            _buf.getByte();
            j = _buf.getByte();
            if (j != 31)
               return false;
            this.p = _buf.getMPInt();
            this.g = _buf.getMPInt();
            bits = (new BigInteger(1, this.p)).bitLength();
            if (bits < this.min || bits > this.max)
               return false;
            this.dh.setP(this.p);
            this.dh.setG(this.g);
            this.e = this.dh.getE();
            this.packet.reset();
            this.buf.putByte((byte)32);
            this.buf.putMPInt(this.e);
            this.state = 33;
            return true;
         case 33:
            j = _buf.getInt();
            j = _buf.getByte();
            j = _buf.getByte();
            if (j != 33)
               return false;
            this.K_S = _buf.getString();
            f = _buf.getMPInt();
            sig_of_H = _buf.getString();
            this.dh.setF(f);
            this.dh.checkRange();
            this.K = encodeAsMPInt(normalize(this.dh.getK()));
            this.buf.reset();
            this.buf.putString(this.V_C);
            this.buf.putString(this.V_S);
            this.buf.putString(this.I_C);
            this.buf.putString(this.I_S);
            this.buf.putString(this.K_S);
            this.buf.putInt(this.min);
            this.buf.putInt(this.preferred);
            this.buf.putInt(this.max);
            this.buf.putMPInt(this.p);
            this.buf.putMPInt(this.g);
            this.buf.putMPInt(this.e);
            this.buf.putMPInt(f);
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
