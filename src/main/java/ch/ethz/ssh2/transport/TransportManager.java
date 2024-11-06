package ch.ethz.ssh2.transport;

import ch.ethz.ssh2.ConnectionInfo;
import ch.ethz.ssh2.ConnectionMonitor;
import ch.ethz.ssh2.DHGexParameters;
import ch.ethz.ssh2.crypto.CryptoWishList;
import ch.ethz.ssh2.crypto.cipher.BlockCipher;
import ch.ethz.ssh2.crypto.digest.MAC;
import ch.ethz.ssh2.log.Logger;
import ch.ethz.ssh2.packets.PacketDisconnect;
import ch.ethz.ssh2.packets.TypesReader;
import ch.ethz.ssh2.signature.DSAPrivateKey;
import ch.ethz.ssh2.signature.RSAPrivateKey;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public abstract class TransportManager {
   private static final Logger log = Logger.getLogger(TransportManager.class);
   private final List<TransportManager.AsynchronousEntry> asynchronousQueue = new ArrayList();
   private Thread asynchronousThread = null;
   private boolean asynchronousPending = false;
   private final Object connectionSemaphore = new Object();
   private boolean flagKexOngoing = false;
   private boolean connectionClosed = false;
   private Throwable reasonClosedCause = null;
   private TransportConnection tc;
   private KexManager km;
   private final List<TransportManager.HandlerEntry> messageHandlers = new ArrayList();
   private Thread receiveThread;
   private List<ConnectionMonitor> connectionMonitors = new ArrayList();
   private boolean monitorsWereInformed = false;
   private boolean idle;

   protected void init(TransportConnection tc, KexManager km) {
      this.tc = tc;
      this.km = km;
   }

   public int getPacketOverheadEstimate() {
      return this.tc.getPacketOverheadEstimate();
   }

   public ConnectionInfo getConnectionInfo(int kexNumber) throws IOException {
      return this.km.getOrWaitForConnectionInfo(kexNumber);
   }

   public Throwable getReasonClosedCause() {
      synchronized(this.connectionSemaphore) {
         return this.reasonClosedCause;
      }
   }

   public byte[] getSessionIdentifier() {
      return this.km.sessionId;
   }

   public void close(Throwable cause) {
      this.close(cause, false);
   }

   public abstract void close(Throwable var1, boolean var2);

   public void close(Socket sock, Throwable cause, boolean useDisconnectPacket) {
      if (!useDisconnectPacket) {
         try {
            sock.close();
         } catch (IOException var11) {
         }
      }

      synchronized(this.connectionSemaphore) {
         if (!this.connectionClosed) {
            if (useDisconnectPacket) {
               try {
                  byte[] msg = (new PacketDisconnect(11, cause.getMessage(), "")).getPayload();
                  if (this.tc != null) {
                     this.tc.sendMessage(msg);
                  }
               } catch (IOException var10) {
               }

               try {
                  sock.close();
               } catch (IOException var9) {
               }
            }

            this.connectionClosed = true;
            this.reasonClosedCause = cause;
         }

         this.connectionSemaphore.notifyAll();
      }

      List<ConnectionMonitor> monitors = new ArrayList();
      synchronized(this) {
         if (!this.monitorsWereInformed) {
            this.monitorsWereInformed = true;
            monitors.addAll(this.connectionMonitors);
         }
      }

      Iterator var6 = monitors.iterator();

      while(var6.hasNext()) {
         ConnectionMonitor cmon = (ConnectionMonitor)var6.next();

         try {
            cmon.connectionLost(this.reasonClosedCause);
         } catch (Exception var8) {
         }
      }

   }

   protected void startReceiver() throws IOException {
      this.receiveThread = new Thread(new Runnable() {
         public void run() {
            try {
               TransportManager.this.receiveLoop();
            } catch (IOException var6) {
               TransportManager.this.close(var6);
               TransportManager.log.warning("Receive thread: error in receiveLoop: " + var6.getMessage());
            }

            if (TransportManager.log.isDebugEnabled()) {
               TransportManager.log.debug("Receive thread: back from receiveLoop");
            }

            if (TransportManager.this.km != null) {
               try {
                  TransportManager.this.km.handleMessage((byte[])null, 0);
               } catch (IOException var5) {
               }
            }

            Iterator var2 = TransportManager.this.messageHandlers.iterator();

            while(var2.hasNext()) {
               TransportManager.HandlerEntry he = (TransportManager.HandlerEntry)var2.next();

               try {
                  he.mh.handleMessage((byte[])null, 0);
               } catch (IOException var4) {
               }
            }

         }
      });
      this.receiveThread.setDaemon(true);
      this.receiveThread.start();
   }

   public void registerMessageHandler(MessageHandler mh, int low, int high) {
      TransportManager.HandlerEntry he = new TransportManager.HandlerEntry((TransportManager.HandlerEntry)null);
      he.mh = mh;
      he.low = low;
      he.high = high;
      synchronized(this.messageHandlers) {
         this.messageHandlers.add(he);
      }
   }

   public void removeMessageHandler(MessageHandler mh, int low, int high) {
      synchronized(this.messageHandlers) {
         for(int i = 0; i < this.messageHandlers.size(); ++i) {
            TransportManager.HandlerEntry he = (TransportManager.HandlerEntry)this.messageHandlers.get(i);
            if (he.mh == mh && he.low == low && he.high == high) {
               this.messageHandlers.remove(i);
               break;
            }
         }

      }
   }

   public void sendKexMessage(byte[] msg) throws IOException {
      synchronized(this.connectionSemaphore) {
         if (this.connectionClosed) {
            throw new IOException("Sorry, this connection is closed.", this.reasonClosedCause);
         } else {
            this.flagKexOngoing = true;

            try {
               this.tc.sendMessage(msg);
            } catch (IOException var4) {
               this.close(var4);
               throw var4;
            }

         }
      }
   }

   public void kexFinished() throws IOException {
      synchronized(this.connectionSemaphore) {
         this.flagKexOngoing = false;
         this.connectionSemaphore.notifyAll();
      }
   }

   public void forceKeyExchange(CryptoWishList cwl, DHGexParameters dhgex, DSAPrivateKey dsa, RSAPrivateKey rsa) throws IOException {
      synchronized(this.connectionSemaphore) {
         if (this.connectionClosed) {
            throw new IOException("Sorry, this connection is closed.", this.reasonClosedCause);
         }
      }

      this.km.initiateKEX(cwl, dhgex, dsa, rsa);
   }

   public void changeRecvCipher(BlockCipher bc, MAC mac) {
      this.tc.changeRecvCipher(bc, mac);
   }

   public void changeSendCipher(BlockCipher bc, MAC mac) {
      this.tc.changeSendCipher(bc, mac);
   }

   public void sendAsynchronousMessage(byte[] msg) throws IOException {
      this.sendAsynchronousMessage(msg, (Runnable)null);
   }

   public void sendAsynchronousMessage(byte[] msg, Runnable run) throws IOException {
      synchronized(this.asynchronousQueue) {
         this.asynchronousQueue.add(new TransportManager.AsynchronousEntry(msg, run));
         this.asynchronousPending = true;
         if (this.asynchronousQueue.size() > 100) {
            throw new IOException("Error: the peer is not consuming our asynchronous replies.");
         } else {
            if (this.asynchronousThread == null) {
               this.asynchronousThread = new TransportManager.AsynchronousWorker((TransportManager.AsynchronousWorker)null);
               this.asynchronousThread.setDaemon(true);
               this.asynchronousThread.start();
            }

            this.asynchronousQueue.notifyAll();
         }
      }
   }

   public void setConnectionMonitors(List<ConnectionMonitor> monitors) {
      synchronized(this) {
         this.connectionMonitors = new ArrayList();
         this.connectionMonitors.addAll(monitors);
      }
   }

   public void sendMessage(byte[] msg) throws IOException {
      synchronized(this.asynchronousQueue) {
         while(this.asynchronousPending) {
            try {
               this.asynchronousQueue.wait(1000L);
            } catch (InterruptedException var4) {
               throw new InterruptedIOException(var4.getMessage());
            }
         }
      }

      this.sendMessageImmediate(msg);
   }

   public void sendMessageImmediate(byte[] msg) throws IOException {
      if (Thread.currentThread() == this.receiveThread) {
         throw new IOException("Assertion error: sendMessage may never be invoked by the receiver thread!");
      } else {
         synchronized(this.connectionSemaphore) {
            while(!this.connectionClosed) {
               if (!this.flagKexOngoing) {
                  try {
                     this.tc.sendMessage(msg);
                     this.idle = false;
                  } catch (IOException var4) {
                     this.close(var4);
                     throw var4;
                  }

                  return;
               }

               try {
                  this.connectionSemaphore.wait();
               } catch (InterruptedException var5) {
                  throw new InterruptedIOException(var5.getMessage());
               }
            }

            throw new IOException("Sorry, this connection is closed.", this.reasonClosedCause);
         }
      }
   }

   public void receiveLoop() throws IOException {
      byte[] msg = new byte['袸'];

      while(true) {
         int msglen;
         TypesReader tr;
         do {
            while(true) {
               int type;
               do {
                  while(true) {
                     try {
                        msglen = this.tc.receiveMessage(msg, 0, msg.length);
                        break;
                     } catch (SocketTimeoutException var9) {
                        if (!this.idle) {
                           throw var9;
                        }

                        log.debug("Ignoring socket timeout");
                     }
                  }

                  this.idle = true;
                  type = msg[0] & 255;
               } while(type == 2);

               if (type == 4) {
                  break;
               }

               if (type == 3) {
                  throw new IOException("Peer sent UNIMPLEMENTED message, that should not happen.");
               }

               if (type == 1) {
                  tr = new TypesReader(msg, 0, msglen);
                  tr.readByte();
                  int reason_code = tr.readUINT32();
                  StringBuilder reasonBuffer = new StringBuilder();
                  reasonBuffer.append(tr.readString("UTF-8"));
                  if (reasonBuffer.length() > 255) {
                     reasonBuffer.setLength(255);
                     reasonBuffer.setCharAt(254, '.');
                     reasonBuffer.setCharAt(253, '.');
                     reasonBuffer.setCharAt(252, '.');
                  }

                  for(int i = 0; i < reasonBuffer.length(); ++i) {
                     char c = reasonBuffer.charAt(i);
                     if (c < ' ' || c > '~') {
                        reasonBuffer.setCharAt(i, '�');
                     }
                  }

                  throw new IOException("Peer sent DISCONNECT message (reason code " + reason_code + "): " + reasonBuffer.toString());
               }

               if (type != 20 && type != 21 && (type < 30 || type > 49)) {
                  MessageHandler mh = null;
                  Iterator var6 = this.messageHandlers.iterator();

                  while(var6.hasNext()) {
                     TransportManager.HandlerEntry he = (TransportManager.HandlerEntry)var6.next();
                     if (he.low <= type && type <= he.high) {
                        mh = he.mh;
                        break;
                     }
                  }

                  if (mh == null) {
                     throw new IOException("Unexpected SSH message (type " + type + ")");
                  }

                  mh.handleMessage(msg, msglen);
               } else {
                  this.km.handleMessage(msg, msglen);
               }
            }
         } while(!log.isDebugEnabled());

         tr = new TypesReader(msg, 0, msglen);
         tr.readByte();
         tr.readBoolean();
         StringBuilder debugMessageBuffer = new StringBuilder();
         debugMessageBuffer.append(tr.readString("UTF-8"));

         for(int i = 0; i < debugMessageBuffer.length(); ++i) {
            char c = debugMessageBuffer.charAt(i);
            if (c < ' ' || c > '~') {
               debugMessageBuffer.setCharAt(i, '�');
            }
         }

         log.debug("DEBUG Message from remote: '" + debugMessageBuffer.toString() + "'");
      }
   }

   private static final class AsynchronousEntry {
      public byte[] msg;
      public Runnable run;

      public AsynchronousEntry(byte[] msg, Runnable run) {
         this.msg = msg;
         this.run = run;
      }
   }

   private final class AsynchronousWorker extends Thread {
      private AsynchronousWorker() {
      }

      public void run() {
         while(true) {
            TransportManager.AsynchronousEntry item;
            synchronized(TransportManager.this.asynchronousQueue) {
               if (TransportManager.this.asynchronousQueue.size() == 0) {
                  TransportManager.this.asynchronousPending = false;
                  TransportManager.this.asynchronousQueue.notifyAll();

                  try {
                     TransportManager.this.asynchronousQueue.wait(2000L);
                  } catch (InterruptedException var6) {
                  }

                  if (TransportManager.this.asynchronousQueue.size() == 0) {
                     TransportManager.this.asynchronousThread = null;
                     return;
                  }
               }

               item = (TransportManager.AsynchronousEntry)TransportManager.this.asynchronousQueue.remove(0);
            }

            try {
               TransportManager.this.sendMessageImmediate(item.msg);
            } catch (IOException var5) {
               return;
            }

            if (item.run != null) {
               try {
                  item.run.run();
               } catch (Exception var4) {
               }
            }
         }
      }

      // $FF: synthetic method
      AsynchronousWorker(TransportManager.AsynchronousWorker var2) {
         this();
      }
   }

   private static final class HandlerEntry {
      MessageHandler mh;
      int low;
      int high;

      private HandlerEntry() {
      }

      // $FF: synthetic method
      HandlerEntry(TransportManager.HandlerEntry var1) {
         this();
      }
   }
}
