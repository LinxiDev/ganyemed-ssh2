package ch.ethz.ssh2.jsch;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

public class ProxySOCKS5 implements Proxy {
   private static int DEFAULTPORT = 1080;

   private String proxy_host;

   private int proxy_port;

   private InputStream in;

   private OutputStream out;

   private Socket socket;

   private String user;

   private String passwd;

   public ProxySOCKS5(String proxy_host) {
      int port = DEFAULTPORT;
      String host = proxy_host;
      if (proxy_host.indexOf(':') != -1)
         try {
            host = proxy_host.substring(0, proxy_host.indexOf(':'));
            port = Integer.parseInt(proxy_host.substring(proxy_host.indexOf(':') + 1));
         } catch (Exception exception) {}
      this.proxy_host = host;
      this.proxy_port = port;
   }

   public ProxySOCKS5(String proxy_host, int proxy_port) {
      this.proxy_host = proxy_host;
      this.proxy_port = proxy_port;
   }

   public void setUserPasswd(String user, String passwd) {
      this.user = user;
      this.passwd = passwd;
   }

   public void connect(SocketFactory socket_factory, String host, int port, int timeout) throws JSchException {
      try {
         if (socket_factory == null) {
            this.socket = Util.createSocket(this.proxy_host, this.proxy_port, timeout);
            this.in = this.socket.getInputStream();
            this.out = this.socket.getOutputStream();
         } else {
            this.socket = socket_factory.createSocket(this.proxy_host, this.proxy_port);
            this.in = socket_factory.getInputStream(this.socket);
            this.out = socket_factory.getOutputStream(this.socket);
         }
         if (timeout > 0)
            this.socket.setSoTimeout(timeout);
         this.socket.setTcpNoDelay(true);
         byte[] buf = new byte[1024];
         int index = 0;
         buf[index++] = 5;
         buf[index++] = 2;
         buf[index++] = 0;
         buf[index++] = 2;
         this.out.write(buf, 0, index);
         fill(this.in, buf, 2);
         boolean check = false;
         switch (buf[1] & 0xFF) {
            case 0:
               check = true;
               break;
            case 2:
               if (this.user == null || this.passwd == null)
                  break;
               index = 0;
               buf[index++] = 1;
               buf[index++] = (byte)this.user.length();
               System.arraycopy(Util.str2byte(this.user), 0, buf, index, this.user.length());
               index += this.user.length();
               buf[index++] = (byte)this.passwd.length();
               System.arraycopy(Util.str2byte(this.passwd), 0, buf, index, this.passwd.length());
               index += this.passwd.length();
               this.out.write(buf, 0, index);
               fill(this.in, buf, 2);
               if (buf[1] == 0)
                  check = true;
               break;
         }
         if (!check) {
            try {
               this.socket.close();
            } catch (Exception exception) {}
            throw new JSchProxyException("fail in SOCKS5 proxy");
         }
         index = 0;
         buf[index++] = 5;
         buf[index++] = 1;
         buf[index++] = 0;
         byte[] hostb = Util.str2byte(host);
         int len = hostb.length;
         buf[index++] = 3;
         buf[index++] = (byte)len;
         System.arraycopy(hostb, 0, buf, index, len);
         index += len;
         buf[index++] = (byte)(port >>> 8);
         buf[index++] = (byte)(port & 0xFF);
         this.out.write(buf, 0, index);
         fill(this.in, buf, 4);
         if (buf[1] != 0) {
            try {
               this.socket.close();
            } catch (Exception exception) {}
            throw new JSchProxyException("ProxySOCKS5: server returns " + buf[1]);
         }
         switch (buf[3] & 0xFF) {
            case 1:
               fill(this.in, buf, 6);
               break;
            case 3:
               fill(this.in, buf, 1);
               fill(this.in, buf, (buf[0] & 0xFF) + 2);
               break;
            case 4:
               fill(this.in, buf, 18);
               break;
         }
      } catch (RuntimeException e) {
         throw e;
      } catch (Exception e) {
         try {
            if (this.socket != null)
               this.socket.close();
         } catch (Exception exception) {}
         String message = "ProxySOCKS5: " + e.toString();
         throw new JSchProxyException(message, e);
      }
   }

   public InputStream getInputStream() {
      return this.in;
   }

   public OutputStream getOutputStream() {
      return this.out;
   }

   public Socket getSocket() {
      return this.socket;
   }

   public void close() {
      try {
         if (this.in != null)
            this.in.close();
         if (this.out != null)
            this.out.close();
         if (this.socket != null)
            this.socket.close();
      } catch (Exception exception) {}
      this.in = null;
      this.out = null;
      this.socket = null;
   }

   public static int getDefaultPort() {
      return DEFAULTPORT;
   }

   private void fill(InputStream in, byte[] buf, int len) throws JSchException, IOException {
      int s = 0;
      while (s < len) {
         int i = in.read(buf, s, len - s);
         if (i <= 0)
            throw new JSchProxyException("ProxySOCKS5: stream is closed");
         s += i;
      }
   }
}
