package ch.ethz.ssh2;

import ch.ethz.ssh2.channel.Channel;
import ch.ethz.ssh2.channel.ChannelManager;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;

public class LocalStreamForwarder {
   private ChannelManager cm;
   private Channel cn;

   LocalStreamForwarder(ChannelManager cm, String host_to_connect, int port_to_connect) throws IOException {
      this.cm = cm;
      this.cn = cm.openDirectTCPIPChannel(host_to_connect, port_to_connect, InetAddress.getLocalHost().getHostAddress(), 0);
   }

   public InputStream getInputStream() throws IOException {
      return this.cn.getStdoutStream();
   }

   public OutputStream getOutputStream() throws IOException {
      return this.cn.getStdinStream();
   }

   public void close() throws IOException {
      this.cm.closeChannel(this.cn, "Closed due to user request.", true);
   }
}
