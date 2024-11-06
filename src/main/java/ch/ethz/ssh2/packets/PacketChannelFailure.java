package ch.ethz.ssh2.packets;

public class PacketChannelFailure {
   byte[] payload;
   public int recipientChannelID;

   public PacketChannelFailure(int recipientChannelID) {
      this.recipientChannelID = recipientChannelID;
   }

   public byte[] getPayload() {
      if (this.payload == null) {
         TypesWriter tw = new TypesWriter();
         tw.writeByte(100);
         tw.writeUINT32(this.recipientChannelID);
         this.payload = tw.getBytes();
      }

      return this.payload;
   }
}
