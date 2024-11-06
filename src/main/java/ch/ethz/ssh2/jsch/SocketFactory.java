package ch.ethz.ssh2.jsch;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.UnknownHostException;

public interface SocketFactory {
   Socket createSocket(String var1, int var2) throws IOException, UnknownHostException;

   InputStream getInputStream(Socket var1) throws IOException;

   OutputStream getOutputStream(Socket var1) throws IOException;
}
