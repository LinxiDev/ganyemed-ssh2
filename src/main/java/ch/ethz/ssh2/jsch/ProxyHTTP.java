package ch.ethz.ssh2.jsch;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

public class ProxyHTTP implements Proxy {
   private static int DEFAULTPORT = 80;
   private String proxy_host;
   private int proxy_port;
   private InputStream in;
   private OutputStream out;
   private Socket socket;
   private String user;
   private String passwd;

   public ProxyHTTP(String proxy_host) {
      int port = DEFAULTPORT;
      String host = proxy_host;
      if (proxy_host.indexOf(58) != -1) {
         try {
            host = proxy_host.substring(0, proxy_host.indexOf(58));
            port = Integer.parseInt(proxy_host.substring(proxy_host.indexOf(58) + 1));
         } catch (Exception var5) {
         }
      }

      this.proxy_host = host;
      this.proxy_port = port;
   }

   public ProxyHTTP(String proxy_host, int proxy_port) {
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

         if (timeout > 0) {
            this.socket.setSoTimeout(timeout);
         }

         this.socket.setTcpNoDelay(true);
         this.out.write(Util.str2byte("CONNECT " + host + ":" + port + " HTTP/1.0\r\n"));
         if (this.user != null && this.passwd != null) {
            byte[] code = Util.str2byte(this.user + ":" + this.passwd);
            code = Util.toBase64(code, 0, code.length, true);
            this.out.write(Util.str2byte("Proxy-Authorization: Basic "));
            this.out.write(code);
            this.out.write(Util.str2byte("\r\n"));
         }

         this.out.write(Util.str2byte("\r\n"));
         this.out.flush();
         int foo = 0;
         StringBuilder sb = new StringBuilder();

         while(foo >= 0) {
            foo = this.in.read();
            if (foo != 13) {
               sb.append((char)foo);
            } else {
               foo = this.in.read();
               if (foo != 10) {
                  continue;
               }
               break;
            }
         }

         if (foo < 0) {
            throw new IOException();
         } else {
            String response = sb.toString();
            String reason = "Unknow reason";
            int code = -1;

            int count;
            try {
               foo = response.indexOf(32);
               count = response.indexOf(32, foo + 1);
               code = Integer.parseInt(response.substring(foo + 1, count));
               reason = response.substring(count + 1);
            } catch (Exception var12) {
            }

            if (code != 200) {
               throw new IOException("proxy error: " + reason);
            } else {
               boolean var17 = false;

               do {
                  count = 0;

                  while(foo >= 0) {
                     foo = this.in.read();
                     if (foo != 13) {
                        ++count;
                     } else {
                        foo = this.in.read();
                        if (foo == 10) {
                           break;
                        }
                     }
                  }

                  if (foo < 0) {
                     throw new IOException();
                  }
               } while(count != 0);

            }
         }
      } catch (RuntimeException var13) {
         throw var13;
      } catch (Exception var14) {
         try {
            if (this.socket != null) {
               this.socket.close();
            }
         } catch (Exception var11) {
         }

         String message = "ProxyHTTP: " + var14.toString();
         throw new JSchProxyException(message, var14);
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
         if (this.in != null) {
            this.in.close();
         }

         if (this.out != null) {
            this.out.close();
         }

         if (this.socket != null) {
            this.socket.close();
         }
      } catch (Exception var2) {
      }

      this.in = null;
      this.out = null;
      this.socket = null;
   }

   public static int getDefaultPort() {
      return DEFAULTPORT;
   }
}
