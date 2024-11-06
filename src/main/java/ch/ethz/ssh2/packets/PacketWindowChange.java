package ch.ethz.ssh2.packets;

public class PacketWindowChange {
   byte[] payload;
   public int recipientChannelID;
   public int character_width;
   public int character_height;
   public int pixel_width;
   public int pixel_height;

   public PacketWindowChange(int recipientChannelID, int character_width, int character_height, int pixel_width, int pixel_height) {
      this.recipientChannelID = recipientChannelID;
      this.character_width = character_width;
      this.character_height = character_height;
      this.pixel_width = pixel_width;
      this.pixel_height = pixel_height;
   }

   public byte[] getPayload() {
      if (this.payload == null) {
         TypesWriter tw = new TypesWriter();
         tw.writeByte(98);
         tw.writeUINT32(this.recipientChannelID);
         tw.writeString("window-change");
         tw.writeBoolean(false);
         tw.writeUINT32(this.character_width);
         tw.writeUINT32(this.character_height);
         tw.writeUINT32(this.pixel_width);
         tw.writeUINT32(this.pixel_height);
         this.payload = tw.getBytes();
      }

      return this.payload;
   }
}
