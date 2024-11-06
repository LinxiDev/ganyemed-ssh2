package ch.ethz.ssh2.jsch;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.nio.file.Path;
import java.nio.file.Paths;
/* loaded from: SSHAgentConnector.class */
public class SSHAgentConnector implements AgentConnector {
   private static final int MAX_AGENT_REPLY_LEN = 262144;
   private USocketFactory factory;
   private Path usocketPath;

   public SSHAgentConnector() throws AgentProxyException {
      this(getUSocketFactory(), getSshAuthSocket());
   }

   public SSHAgentConnector(Path usocketPath) throws AgentProxyException {
      this(getUSocketFactory(), usocketPath);
   }

   public SSHAgentConnector(USocketFactory factory) throws AgentProxyException {
      this(factory, getSshAuthSocket());
   }

   public SSHAgentConnector(USocketFactory factory, Path usocketPath) {
      this.factory = factory;
      this.usocketPath = usocketPath;
   }

   public String getName() {
      return "ssh-agent";
   }

   public boolean isAvailable() {
      try {
         SocketChannel foo = open();
         if (foo != null) {
            foo.close();
            return true;
         }
         return true;
      } catch (IOException e) {
         return false;
      }
   }

   private SocketChannel open() throws IOException {
      return this.factory.connect(this.usocketPath);
   }

   public void query(Buffer buffer) throws AgentProxyException {
      try {
         SocketChannel sock = open();
         try {
            writeFull(sock, buffer, 0, buffer.getLength());
            buffer.rewind();
            readFull(sock, buffer, 0, 4);
            int i = buffer.getInt();
            if (i <= 0 || i > MAX_AGENT_REPLY_LEN) {
               throw new AgentProxyException("Illegal length: " + i);
            }
            buffer.rewind();
            buffer.checkFreeSize(i);
            readFull(sock, buffer, 0, i);
            if (sock != null) {
               sock.close();
            }
         } catch (Throwable th) {
            if (sock != null) {
               sock.close();
            }
            throw th;
         }
      } catch (IOException e) {
         throw new AgentProxyException(e.toString(), e);
      }
   }

   private static USocketFactory getUSocketFactory() throws AgentProxyException {
      try {
         return new UnixDomainSocketFactory();
      } catch (AgentProxyException e) {
         try {
            return new UnixDomainSocketFactory();
         } catch (AgentProxyException ee) {
            ee.addSuppressed(e);
            throw e;
         } catch (NoClassDefFoundError ee2) {
            AgentProxyException eee = new AgentProxyException("junixsocket library unavailable");
            eee.addSuppressed(e);
            eee.addSuppressed(ee2);
            throw eee;
         }
      }
   }

   private static Path getSshAuthSocket() throws AgentProxyException {
      String ssh_auth_sock = Util.getSystemEnv("SSH_AUTH_SOCK");
      if (ssh_auth_sock == null) {
         throw new AgentProxyException("SSH_AUTH_SOCK is not defined.");
      }
      return Paths.get(ssh_auth_sock, new String[0]);
   }

   private static int readFull(SocketChannel sock, Buffer buffer, int s, int len) throws IOException {
      ByteBuffer bb = ByteBuffer.wrap(buffer.buffer, s, len);
      while (len > 0) {
         int j = sock.read(bb);
         if (j < 0) {
            return -1;
         }
         if (j > 0) {
            len -= j;
         }
      }
      return len;
   }

   private static int writeFull(SocketChannel sock, Buffer buffer, int s, int len) throws IOException {
      ByteBuffer bb = ByteBuffer.wrap(buffer.buffer, s, len);
      while (len > 0) {
         int j = sock.write(bb);
         if (j < 0) {
            return -1;
         }
         if (j > 0) {
            len -= j;
         }
      }
      return len;
   }
}