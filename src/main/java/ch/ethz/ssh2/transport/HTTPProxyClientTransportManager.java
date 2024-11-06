package ch.ethz.ssh2.transport;

import ch.ethz.ssh2.HTTPProxyData;
import ch.ethz.ssh2.HTTPProxyException;
import ch.ethz.ssh2.crypto.Base64;
import ch.ethz.ssh2.util.StringEncoder;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;

public class HTTPProxyClientTransportManager extends ClientTransportManager {
   private HTTPProxyData pd;

   public HTTPProxyClientTransportManager(HTTPProxyData pd) {
      this.pd = pd;
   }

   protected void connect(String hostname, int port, int connectTimeout) throws IOException {
      InetAddress addr = createInetAddress(this.pd.proxyHost);
      this.sock.connect(new InetSocketAddress(addr, this.pd.proxyPort), connectTimeout);
      StringBuilder sb = new StringBuilder();
      sb.append("CONNECT ");
      sb.append(hostname);
      sb.append(':');
      sb.append(port);
      sb.append(" HTTP/1.0\r\n");
      if (this.pd.proxyUser != null && this.pd.proxyPass != null) {
         String credentials = this.pd.proxyUser + ":" + this.pd.proxyPass;
         char[] encoded = Base64.encode(StringEncoder.GetBytes(credentials));
         sb.append("Proxy-Authorization: Basic ");
         sb.append(encoded);
         sb.append("\r\n");
      }

      if (this.pd.requestHeaderLines != null) {
         for(int i = 0; i < this.pd.requestHeaderLines.length; ++i) {
            if (this.pd.requestHeaderLines[i] != null) {
               sb.append(this.pd.requestHeaderLines[i]);
               sb.append("\r\n");
            }
         }
      }

      sb.append("\r\n");
      OutputStream out = this.sock.getOutputStream();
      out.write(StringEncoder.GetBytes(sb.toString()));
      out.flush();
      byte[] buffer = new byte[1024];
      InputStream in = this.sock.getInputStream();
      int len = ClientServerHello.readLineRN(in, buffer);
      String httpReponse = StringEncoder.GetString(buffer, 0, len);
      if (!httpReponse.startsWith("HTTP/")) {
         throw new IOException("The proxy did not send back a valid HTTP response.");
      } else if (httpReponse.length() >= 14 && httpReponse.charAt(8) == ' ' && httpReponse.charAt(12) == ' ') {
         int errorCode;
         try {
            errorCode = Integer.parseInt(httpReponse.substring(9, 12));
         } catch (NumberFormatException var13) {
            throw new IOException("The proxy did not send back a valid HTTP response.");
         }

         if (errorCode >= 0 && errorCode <= 999) {
            if (errorCode != 200) {
               throw new HTTPProxyException(httpReponse.substring(13), errorCode);
            } else {
               do {
                  len = ClientServerHello.readLineRN(in, buffer);
               } while(len != 0);

            }
         } else {
            throw new IOException("The proxy did not send back a valid HTTP response.");
         }
      } else {
         throw new IOException("The proxy did not send back a valid HTTP response.");
      }
   }
}
