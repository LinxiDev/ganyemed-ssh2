package ch.ethz.ssh2.jsch;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

public interface Proxy {
   void connect(SocketFactory var1, String var2, int var3, int var4) throws Exception;

   InputStream getInputStream();

   OutputStream getOutputStream();

   Socket getSocket();

   void close();
}
