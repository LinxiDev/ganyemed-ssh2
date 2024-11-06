package ch.ethz.ssh2.jsch;

public class Buffer {
   final byte[] tmp;
   byte[] buffer;
   int index;
   int s;
   private static final int buffer_margin = 128;

   public Buffer(int size) {
      this.tmp = new byte[4];
      this.buffer = new byte[size];
      this.index = 0;
      this.s = 0;
   }

   public Buffer(byte[] buffer) {
      this.tmp = new byte[4];
      this.buffer = buffer;
      this.index = 0;
      this.s = 0;
   }

   public Buffer() {
      this(20480);
   }

   public void putByte(byte foo) {
      this.buffer[this.index++] = foo;
   }

   public void putByte(byte[] foo) {
      this.putByte(foo, 0, foo.length);
   }

   public void putByte(byte[] foo, int begin, int length) {
      System.arraycopy(foo, begin, this.buffer, this.index, length);
      this.index += length;
   }

   public void putString(byte[] foo) {
      this.putString(foo, 0, foo.length);
   }

   public void putString(byte[] foo, int begin, int length) {
      this.putInt(length);
      this.putByte(foo, begin, length);
   }

   public void putInt(int val) {
      this.tmp[0] = (byte)(val >>> 24);
      this.tmp[1] = (byte)(val >>> 16);
      this.tmp[2] = (byte)(val >>> 8);
      this.tmp[3] = (byte)val;
      System.arraycopy(this.tmp, 0, this.buffer, this.index, 4);
      this.index += 4;
   }

   public void putLong(long val) {
      this.tmp[0] = (byte)((int)(val >>> 56));
      this.tmp[1] = (byte)((int)(val >>> 48));
      this.tmp[2] = (byte)((int)(val >>> 40));
      this.tmp[3] = (byte)((int)(val >>> 32));
      System.arraycopy(this.tmp, 0, this.buffer, this.index, 4);
      this.tmp[0] = (byte)((int)(val >>> 24));
      this.tmp[1] = (byte)((int)(val >>> 16));
      this.tmp[2] = (byte)((int)(val >>> 8));
      this.tmp[3] = (byte)((int)val);
      System.arraycopy(this.tmp, 0, this.buffer, this.index + 4, 4);
      this.index += 8;
   }

   void skip(int n) {
      this.index += n;
   }

   void putPad(int n) {
      while(n > 0) {
         this.buffer[this.index++] = 0;
         --n;
      }

   }

   public void putMPInt(byte[] foo) {
      int i = foo.length;
      if ((foo[0] & 128) != 0) {
         ++i;
         this.putInt(i);
         this.putByte((byte)0);
      } else {
         this.putInt(i);
      }

      this.putByte(foo);
   }

   public int getLength() {
      return this.index - this.s;
   }

   public int getOffSet() {
      return this.s;
   }

   public void setOffSet(int s) {
      this.s = s;
   }

   public long getLong() {
      long foo = (long)this.getInt() & 4294967295L;
      foo = foo << 32 | (long)this.getInt() & 4294967295L;
      return foo;
   }

   public int getInt() {
      int foo = this.getShort();
      foo = foo << 16 & -65536 | this.getShort() & '\uffff';
      return foo;
   }

   public long getUInt() {
      long foo = 0L;
      long bar = 0L;
      foo = (long)this.getByte();
      foo = foo << 8 & 65280L | (long)(this.getByte() & 255);
      bar = (long)this.getByte();
      bar = bar << 8 & 65280L | (long)(this.getByte() & 255);
      foo = foo << 16 & -65536L | bar & 65535L;
      return foo;
   }

   int getShort() {
      int foo = this.getByte();
      foo = foo << 8 & '\uff00' | this.getByte() & 255;
      return foo;
   }

   public int getByte() {
      return this.buffer[this.s++] & 255;
   }

   public void getByte(byte[] foo) {
      this.getByte(foo, 0, foo.length);
   }

   void getByte(byte[] foo, int start, int len) {
      System.arraycopy(this.buffer, this.s, foo, start, len);
      this.s += len;
   }

   public int getByte(int len) {
      int foo = this.s;
      this.s += len;
      return foo;
   }

   public byte[] getMPInt() {
      int i = this.getInt();
      if (i < 0 || i > 8192) {
         i = 8192;
      }

      byte[] foo = new byte[i];
      this.getByte(foo, 0, i);
      return foo;
   }

   public byte[] getMPIntBits() {
      int bits = this.getInt();
      int bytes = (bits + 7) / 8;
      byte[] foo = new byte[bytes];
      this.getByte(foo, 0, bytes);
      if ((foo[0] & 128) != 0) {
         byte[] bar = new byte[foo.length + 1];
         bar[0] = 0;
         System.arraycopy(foo, 0, bar, 1, foo.length);
         foo = bar;
      }

      return foo;
   }

   public byte[] getString() {
      int i = this.getInt();
      if (i < 0 || i > 262144) {
         i = 262144;
      }

      byte[] foo = new byte[i];
      this.getByte(foo, 0, i);
      return foo;
   }

   byte[] getString(int[] start, int[] len) {
      int i = this.getInt();
      start[0] = this.getByte(i);
      len[0] = i;
      return this.buffer;
   }

   public void reset() {
      this.index = 0;
      this.s = 0;
   }

   public void shift() {
      if (this.s != 0) {
         System.arraycopy(this.buffer, this.s, this.buffer, 0, this.index - this.s);
         this.index -= this.s;
         this.s = 0;
      }
   }

   void rewind() {
      this.s = 0;
   }

   byte getCommand() {
      return this.buffer[5];
   }

   void checkFreeSize(int n) {
      int size = this.index + n + 128;
      if (this.buffer.length < size) {
         int i = this.buffer.length * 2;
         if (i < size) {
            i = size;
         }

         byte[] tmp = new byte[i];
         System.arraycopy(this.buffer, 0, tmp, 0, this.index);
         this.buffer = tmp;
      }

   }

   byte[][] getBytes(int n, String msg) throws Exception {
      byte[][] tmp = new byte[n][];

      for(int i = 0; i < n; ++i) {
         int j = this.getInt();
         if (this.getLength() < j) {
            throw new Exception(msg);
         }

         tmp[i] = new byte[j];
         this.getByte(tmp[i]);
      }

      return tmp;
   }

   static Buffer fromBytes(byte[][] args) {
      int length = args.length * 4;

      for(int i = 0; i < args.length; ++i) {
         length += args[i].length;
      }

      Buffer buf = new Buffer(length);

      for(int i = 0; i < args.length; ++i) {
         buf.putString(args[i]);
      }

      return buf;
   }
}
