package ch.ethz.ssh2;

import java.io.IOException;

public class PacketTypeException extends IOException {
   public PacketTypeException() {
   }

   public PacketTypeException(String message) {
      super(message);
   }

   public PacketTypeException(int packet) {
      super(String.format("The SFTP server sent an unexpected packet type (%d)", packet));
   }
}
