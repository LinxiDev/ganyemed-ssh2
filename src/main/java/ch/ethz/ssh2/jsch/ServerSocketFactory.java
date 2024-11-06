package ch.ethz.ssh2.jsch;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;

public interface ServerSocketFactory {
   ServerSocket createServerSocket(int var1, int var2, InetAddress var3) throws IOException;
}
