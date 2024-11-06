package ch.ethz.ssh2.packets;

public class PacketChannelSuccess {
   byte[] payload;
   public int recipientChannelID;

   public PacketChannelSuccess(int recipientChannelID) {
      this.recipientChannelID = recipientChannelID;
   }

   public byte[] getPayload() {
      if (this.payload == null) {
         TypesWriter tw = new TypesWriter();
         tw.writeByte(99);
         tw.writeUINT32(this.recipientChannelID);
         this.payload = tw.getBytes();
      }

      return this.payload;
   }
}
