package ch.ethz.ssh2.packets;

import java.io.IOException;
import java.io.UnsupportedEncodingException;

public class PacketSessionExecCommand {
   byte[] payload;
   public int recipientChannelID;
   public boolean wantReply;
   public String command;

   public PacketSessionExecCommand(int recipientChannelID, boolean wantReply, String command) {
      this.recipientChannelID = recipientChannelID;
      this.wantReply = wantReply;
      this.command = command;
   }

   public byte[] getPayload() throws IOException {
      return this.getPayload((String)null);
   }

   public byte[] getPayload(String charsetName) throws UnsupportedEncodingException {
      if (this.payload == null) {
         TypesWriter tw = new TypesWriter();
         tw.writeByte(98);
         tw.writeUINT32(this.recipientChannelID);
         tw.writeString("exec");
         tw.writeBoolean(this.wantReply);
         tw.writeString(this.command, charsetName);
         this.payload = tw.getBytes();
      }

      return this.payload;
   }
}
