package ch.ethz.ssh2.channel;

import java.io.IOException;

public class ChannelClosedException extends IOException {
   private static final long serialVersionUID = 1L;

   public ChannelClosedException(String s) {
      super(s);
   }
}
