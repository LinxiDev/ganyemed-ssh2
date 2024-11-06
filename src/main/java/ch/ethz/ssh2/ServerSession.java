package ch.ethz.ssh2;

import java.io.InputStream;
import java.io.OutputStream;

public interface ServerSession {
   InputStream getStdout();

   InputStream getStderr();

   OutputStream getStdin();

   void close();
}
