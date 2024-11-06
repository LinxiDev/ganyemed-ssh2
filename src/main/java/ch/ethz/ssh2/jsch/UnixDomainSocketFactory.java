package ch.ethz.ssh2.jsch;

import java.io.IOException;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.file.Path;

public class UnixDomainSocketFactory implements USocketFactory {
   public UnixDomainSocketFactory() throws AgentProxyException {
      throw new AgentProxyException("UnixDomainSocketFactory requires Java16+.");
   }

   public SocketChannel connect(Path path) throws IOException {
      throw new UnsupportedOperationException("UnixDomainSocketFactory requires Java16+.");
   }

   public ServerSocketChannel bind(Path path) throws IOException {
      throw new UnsupportedOperationException("UnixDomainSocketFactory requires Java16+.");
   }
}
