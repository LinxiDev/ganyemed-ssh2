package ch.ethz.ssh2.jsch;

import java.io.IOException;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.file.Path;

public interface USocketFactory {
   SocketChannel connect(Path var1) throws IOException;

   ServerSocketChannel bind(Path var1) throws IOException;
}
