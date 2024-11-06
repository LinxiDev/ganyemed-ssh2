package ch.ethz.ssh2.packets;

import java.io.IOException;
import java.math.BigInteger;

public class PacketKexDHInit {
   byte[] payload;
   BigInteger e;

   public PacketKexDHInit(BigInteger e) {
      this.e = e;
   }

   public PacketKexDHInit(byte[] payload, int off, int len) throws IOException {
      this.payload = new byte[len];
      System.arraycopy(payload, off, this.payload, 0, len);
      TypesReader tr = new TypesReader(payload, off, len);
      int packet_type = tr.readByte();
      if (packet_type != 30) {
         throw new IOException("This is not a SSH_MSG_KEXDH_INIT! (" + packet_type + ")");
      } else {
         this.e = tr.readMPINT();
         if (tr.remain() != 0) {
            throw new IOException("PADDING IN SSH_MSG_KEXDH_INIT!");
         }
      }
   }

   public BigInteger getE() {
      return this.e;
   }

   public byte[] getPayload() {
      if (this.payload == null) {
         TypesWriter tw = new TypesWriter();
         tw.writeByte(30);
         tw.writeMPInt(this.e);
         this.payload = tw.getBytes();
      }

      return this.payload;
   }
}
