package ch.ethz.ssh2;

import ch.ethz.ssh2.log.Logger;
import ch.ethz.ssh2.packets.TypesReader;
import ch.ethz.ssh2.packets.TypesWriter;
import ch.ethz.ssh2.sftp.ErrorCodes;
import ch.ethz.ssh2.sftp.Packet;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.SocketException;
import java.nio.charset.Charset;
import java.nio.charset.UnsupportedCharsetException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class SFTPv3Client {
   private static final Logger log = Logger.getLogger(SFTPv3Client.class);

   private Session sess;

   private InputStream is;

   private OutputStream os;

   private int protocol_version = 0;

   private int next_request_id = 1000;

   private String charsetName = null;

   private PacketListener listener;

   public static final int SSH_FXF_READ = 1;

   public static final int SSH_FXF_WRITE = 2;

   public static final int SSH_FXF_APPEND = 4;

   public static final int SSH_FXF_CREAT = 8;

   public static final int SSH_FXF_TRUNC = 16;

   public static final int SSH_FXF_EXCL = 32;

   private static final int DEFAULT_MAX_PARALLELISM = 64;

   private int parallelism;

   private Map<Integer, OutstandingReadRequest> pendingReadQueue;

   private Map<Integer, OutstandingStatusRequest> pendingStatusQueue;

   public SFTPv3Client(Connection conn) throws IOException {
      this(conn, new PacketListener() {
         public void read(String packet) {
            SFTPv3Client.log.debug("Read packet " + packet);
         }

         public void write(String packet) {
            SFTPv3Client.log.debug("Write packet " + packet);
         }
      });
   }

   public void setCharset(String charset) throws IOException {
      if (charset == null) {
         this.charsetName = null;
         return;
      }
      try {
         Charset.forName(charset);
      } catch (UnsupportedCharsetException e) {
         throw new IOException("This charset is not supported", e);
      }
      this.charsetName = charset;
   }

   public String getCharset() {
      return this.charsetName;
   }

   private void checkHandleValidAndOpen(SFTPv3FileHandle handle) throws IOException {
      if (handle.client != this)
         throw new IOException("The file handle was created with another SFTPv3FileHandle instance.");
      if (handle.isClosed)
         throw new IOException("The file handle is closed.");
   }

   private void sendMessage(int type, int requestId, byte[] msg, int off, int len) throws IOException {
      this.listener.write(Packet.forName(type));
      int msglen = len + 1;
      if (type != 1)
         msglen += 4;
      this.os.write(msglen >> 24);
      this.os.write(msglen >> 16);
      this.os.write(msglen >> 8);
      this.os.write(msglen);
      this.os.write(type);
      if (type != 1) {
         this.os.write(requestId >> 24);
         this.os.write(requestId >> 16);
         this.os.write(requestId >> 8);
         this.os.write(requestId);
      }
      this.os.write(msg, off, len);
      this.os.flush();
   }

   private void sendMessage(int type, int requestId, byte[] msg) throws IOException {
      sendMessage(type, requestId, msg, 0, msg.length);
   }

   private void readBytes(byte[] buff, int pos, int len) throws IOException {
      while (len > 0) {
         int count = this.is.read(buff, pos, len);
         if (count < 0)
            throw new SocketException("Unexpected end of sftp stream.");
         if (count == 0 || count > len)
            throw new SocketException("Underlying stream implementation is bogus!");
         len -= count;
         pos += count;
      }
   }

   private byte[] receiveMessage(int maxlen) throws IOException {
      byte[] msglen = new byte[4];
      readBytes(msglen, 0, 4);
      int len = (msglen[0] & 0xFF) << 24 | (msglen[1] & 0xFF) << 16 | (msglen[2] & 0xFF) << 8 | msglen[3] & 0xFF;
      if (len > maxlen || len <= 0)
         throw new IOException("Illegal sftp packet len: " + len);
      byte[] msg = new byte[len];
      readBytes(msg, 0, len);
      return msg;
   }

   private int generateNextRequestID() {
      synchronized (this) {
         return this.next_request_id++;
      }
   }

   private void closeHandle(byte[] handle) throws IOException {
      int req_id = generateNextRequestID();
      TypesWriter tw = new TypesWriter();
      tw.writeString(handle, 0, handle.length);
      sendMessage(4, req_id, tw.getBytes());
      expectStatusOKMessage(req_id);
   }

   private SFTPv3FileAttributes readAttrs(TypesReader tr) throws IOException {
      SFTPv3FileAttributes fa = new SFTPv3FileAttributes();
      int flags = tr.readUINT32();
      if ((flags & 0x1) != 0) {
         log.debug("SSH_FILEXFER_ATTR_SIZE");
         fa.size = Long.valueOf(tr.readUINT64());
      }
      if ((flags & 0x2) != 0) {
         log.debug("SSH_FILEXFER_ATTR_V3_UIDGID");
         fa.uid = Integer.valueOf(tr.readUINT32());
         fa.gid = Integer.valueOf(tr.readUINT32());
      }
      if ((flags & 0x4) != 0) {
         log.debug("SSH_FILEXFER_ATTR_PERMISSIONS");
         fa.permissions = Integer.valueOf(tr.readUINT32());
      }
      if ((flags & 0x8) != 0) {
         log.debug("SSH_FILEXFER_ATTR_V3_ACMODTIME");
         fa.atime = Integer.valueOf(tr.readUINT32());
         fa.mtime = Integer.valueOf(tr.readUINT32());
      }
      if ((flags & Integer.MIN_VALUE) != 0) {
         int count = tr.readUINT32();
         log.debug("SSH_FILEXFER_ATTR_EXTENDED (" + count + ")");
         while (count > 0) {
            tr.readByteString();
            tr.readByteString();
            count--;
         }
      }
      return fa;
   }

   public SFTPv3FileAttributes fstat(SFTPv3FileHandle handle) throws IOException {
      checkHandleValidAndOpen(handle);
      int req_id = generateNextRequestID();
      TypesWriter tw = new TypesWriter();
      tw.writeString(handle.fileHandle, 0, handle.fileHandle.length);
      log.debug("Sending SSH_FXP_FSTAT...");
      sendMessage(8, req_id, tw.getBytes());
      byte[] resp = receiveMessage(34000);
      TypesReader tr = new TypesReader(resp);
      int t = tr.readByte();
      this.listener.read(Packet.forName(t));
      int rep_id = tr.readUINT32();
      if (rep_id != req_id)
         throw new RequestMismatchException();
      if (t == 105)
         return readAttrs(tr);
      if (t != 101)
         throw new PacketTypeException(t);
      int errorCode = tr.readUINT32();
      String errorMessage = tr.readString();
      this.listener.read(errorMessage);
      throw new SFTPException(errorMessage, errorCode);
   }

   private SFTPv3FileAttributes statBoth(String path, int statMethod) throws IOException {
      int req_id = generateNextRequestID();
      TypesWriter tw = new TypesWriter();
      tw.writeString(path, this.charsetName);
      log.debug("Sending SSH_FXP_STAT/SSH_FXP_LSTAT...");
      sendMessage(statMethod, req_id, tw.getBytes());
      byte[] resp = receiveMessage(34000);
      TypesReader tr = new TypesReader(resp);
      int t = tr.readByte();
      this.listener.read(Packet.forName(t));
      int rep_id = tr.readUINT32();
      if (rep_id != req_id)
         throw new RequestMismatchException();
      if (t == 105)
         return readAttrs(tr);
      if (t != 101)
         throw new PacketTypeException(t);
      int errorCode = tr.readUINT32();
      String errorMessage = tr.readString();
      this.listener.read(errorMessage);
      throw new SFTPException(errorMessage, errorCode);
   }

   public SFTPv3FileAttributes stat(String path) throws IOException {
      return statBoth(path, 17);
   }

   public SFTPv3FileAttributes lstat(String path) throws IOException {
      return statBoth(path, 7);
   }

   public String readLink(String path) throws IOException {
      int req_id = generateNextRequestID();
      TypesWriter tw = new TypesWriter();
      tw.writeString(path, this.charsetName);
      log.debug("Sending SSH_FXP_READLINK...");
      sendMessage(19, req_id, tw.getBytes());
      byte[] resp = receiveMessage(34000);
      TypesReader tr = new TypesReader(resp);
      int t = tr.readByte();
      this.listener.read(Packet.forName(t));
      int rep_id = tr.readUINT32();
      if (rep_id != req_id)
         throw new RequestMismatchException();
      if (t == 104) {
         int count = tr.readUINT32();
         if (count != 1)
            throw new IOException("The server sent an invalid SSH_FXP_NAME packet.");
         return tr.readString(this.charsetName);
      }
      if (t != 101)
         throw new PacketTypeException(t);
      int errorCode = tr.readUINT32();
      String errorMessage = tr.readString();
      this.listener.read(errorMessage);
      throw new SFTPException(errorMessage, errorCode);
   }

   private void expectStatusOKMessage(int id) throws IOException {
      byte[] resp = receiveMessage(34000);
      TypesReader tr = new TypesReader(resp);
      int t = tr.readByte();
      this.listener.read(Packet.forName(t));
      int rep_id = tr.readUINT32();
      if (rep_id != id)
         throw new RequestMismatchException();
      if (t != 101)
         throw new PacketTypeException(t);
      int errorCode = tr.readUINT32();
      if (errorCode == 0)
         return;
      String errorMessage = tr.readString();
      this.listener.read(errorMessage);
      throw new SFTPException(errorMessage, errorCode);
   }

   public void setstat(String path, SFTPv3FileAttributes attr) throws IOException {
      int req_id = generateNextRequestID();
      TypesWriter tw = new TypesWriter();
      tw.writeString(path, this.charsetName);
      tw.writeBytes(createAttrs(attr));
      log.debug("Sending SSH_FXP_SETSTAT...");
      sendMessage(9, req_id, tw.getBytes());
      expectStatusOKMessage(req_id);
   }

   public void fsetstat(SFTPv3FileHandle handle, SFTPv3FileAttributes attr) throws IOException {
      checkHandleValidAndOpen(handle);
      int req_id = generateNextRequestID();
      TypesWriter tw = new TypesWriter();
      tw.writeString(handle.fileHandle, 0, handle.fileHandle.length);
      tw.writeBytes(createAttrs(attr));
      log.debug("Sending SSH_FXP_FSETSTAT...");
      sendMessage(10, req_id, tw.getBytes());
      expectStatusOKMessage(req_id);
   }

   public void createSymlink(String src, String target) throws IOException {
      int req_id = generateNextRequestID();
      TypesWriter tw = new TypesWriter();
      tw.writeString(target, this.charsetName);
      tw.writeString(src, this.charsetName);
      log.debug("Sending SSH_FXP_SYMLINK...");
      sendMessage(20, req_id, tw.getBytes());
      expectStatusOKMessage(req_id);
   }

   public String canonicalPath(String path) throws IOException {
      int req_id = generateNextRequestID();
      TypesWriter tw = new TypesWriter();
      tw.writeString(path, this.charsetName);
      log.debug("Sending SSH_FXP_REALPATH...");
      sendMessage(16, req_id, tw.getBytes());
      byte[] resp = receiveMessage(34000);
      TypesReader tr = new TypesReader(resp);
      int t = tr.readByte();
      this.listener.read(Packet.forName(t));
      int rep_id = tr.readUINT32();
      if (rep_id != req_id)
         throw new RequestMismatchException();
      if (t == 104) {
         int count = tr.readUINT32();
         if (count != 1)
            throw new IOException("The server sent an invalid SSH_FXP_NAME packet.");
         String name = tr.readString(this.charsetName);
         this.listener.read(name);
         return name;
      }
      if (t != 101)
         throw new PacketTypeException(t);
      int errorCode = tr.readUINT32();
      String errorMessage = tr.readString();
      this.listener.read(errorMessage);
      throw new SFTPException(errorMessage, errorCode);
   }

   private List<SFTPv3DirectoryEntry> scanDirectory(byte[] handle) throws IOException {
      TypesReader tr;
      int t;
      List<SFTPv3DirectoryEntry> files = new ArrayList<>();
      while (true) {
         int req_id = generateNextRequestID();
         TypesWriter tw = new TypesWriter();
         tw.writeString(handle, 0, handle.length);
         log.debug("Sending SSH_FXP_READDIR...");
         sendMessage(12, req_id, tw.getBytes());
         byte[] resp = receiveMessage(34000);
         tr = new TypesReader(resp);
         t = tr.readByte();
         this.listener.read(Packet.forName(t));
         int rep_id = tr.readUINT32();
         if (rep_id != req_id)
            throw new RequestMismatchException();
         if (t == 104) {
            int count = tr.readUINT32();
            log.debug("Parsing " + count + " name entries...");
            while (count > 0) {
               SFTPv3DirectoryEntry dirEnt = new SFTPv3DirectoryEntry();
               dirEnt.filename = tr.readString(this.charsetName);
               dirEnt.longEntry = tr.readString(this.charsetName);
               this.listener.read(dirEnt.longEntry);
               dirEnt.attributes = readAttrs(tr);
               files.add(dirEnt);
               log.debug("File: '" + dirEnt.filename + "'");
               count--;
            }
            continue;
         }
         break;
      }
      if (t != 101)
         throw new PacketTypeException(t);
      int errorCode = tr.readUINT32();
      if (errorCode == 1)
         return files;
      String errorMessage = tr.readString();
      this.listener.read(errorMessage);
      throw new SFTPException(errorMessage, errorCode);
   }

   public final SFTPv3FileHandle openDirectory(String path) throws IOException {
      int req_id = generateNextRequestID();
      TypesWriter tw = new TypesWriter();
      tw.writeString(path, this.charsetName);
      log.debug("Sending SSH_FXP_OPENDIR...");
      sendMessage(11, req_id, tw.getBytes());
      byte[] resp = receiveMessage(34000);
      TypesReader tr = new TypesReader(resp);
      int t = tr.readByte();
      this.listener.read(Packet.forName(t));
      int rep_id = tr.readUINT32();
      if (rep_id != req_id)
         throw new RequestMismatchException();
      if (t == 102) {
         log.debug("Got SSH_FXP_HANDLE.");
         return new SFTPv3FileHandle(this, tr.readByteString());
      }
      if (t != 101)
         throw new PacketTypeException(t);
      int errorCode = tr.readUINT32();
      String errorMessage = tr.readString();
      this.listener.read(errorMessage);
      throw new SFTPException(errorMessage, errorCode);
   }

   private String expandString(byte[] b, int off, int len) {
      StringBuilder sb = new StringBuilder();
      for (int i = 0; i < len; i++) {
         int c = b[off + i] & 0xFF;
         if (c >= 32 && c <= 126) {
            sb.append((char)c);
         } else {
            sb.append(String.format("{0x%s}", new Object[] { Integer.toHexString(c) }));
         }
      }
      return sb.toString();
   }

   private void init() throws IOException {
      int client_version = 3;
      log.debug("Sending SSH_FXP_INIT (3)...");
      TypesWriter tw = new TypesWriter();
      tw.writeUINT32(3);
      sendMessage(1, 0, tw.getBytes());
      log.debug("Waiting for SSH_FXP_VERSION...");
      TypesReader tr = new TypesReader(receiveMessage(34000));
      int t = tr.readByte();
      this.listener.read(Packet.forName(t));
      if (t != 2)
         throw new IOException("The server did not send a SSH_FXP_VERSION packet (got " + t + ")");
      this.protocol_version = tr.readUINT32();
      log.debug("SSH_FXP_VERSION: protocol_version = " + this.protocol_version);
      if (this.protocol_version != 3)
         throw new IOException("Server version " + this.protocol_version + " is currently not supported");
      while (tr.remain() != 0) {
         String name = tr.readString();
         this.listener.read(name);
         byte[] value = tr.readByteString();
         log.debug("SSH_FXP_VERSION: extension: " + name + " = '" + expandString(value, 0, value.length) + "'");
      }
   }

   public int getProtocolVersion() {
      return this.protocol_version;
   }

   public boolean isConnected() {
      return (this.sess.getState() == 2);
   }

   public void close() {
      this.sess.close();
   }

   public List<SFTPv3DirectoryEntry> ls(String dirName) throws IOException {
      SFTPv3FileHandle handle = openDirectory(dirName);
      List<SFTPv3DirectoryEntry> result = scanDirectory(handle.fileHandle);
      closeFile(handle);
      return result;
   }

   public void mkdir(String dirName, int posixPermissions) throws IOException {
      int req_id = generateNextRequestID();
      TypesWriter tw = new TypesWriter();
      tw.writeString(dirName, this.charsetName);
      tw.writeUINT32(4);
      tw.writeUINT32(posixPermissions);
      sendMessage(14, req_id, tw.getBytes());
      expectStatusOKMessage(req_id);
   }

   public void rm(String fileName) throws IOException {
      int req_id = generateNextRequestID();
      TypesWriter tw = new TypesWriter();
      tw.writeString(fileName, this.charsetName);
      sendMessage(13, req_id, tw.getBytes());
      expectStatusOKMessage(req_id);
   }

   public void rmdir(String dirName) throws IOException {
      int req_id = generateNextRequestID();
      TypesWriter tw = new TypesWriter();
      tw.writeString(dirName, this.charsetName);
      sendMessage(15, req_id, tw.getBytes());
      expectStatusOKMessage(req_id);
   }

   public void mv(String oldPath, String newPath) throws IOException {
      int req_id = generateNextRequestID();
      TypesWriter tw = new TypesWriter();
      tw.writeString(oldPath, this.charsetName);
      tw.writeString(newPath, this.charsetName);
      sendMessage(18, req_id, tw.getBytes());
      expectStatusOKMessage(req_id);
   }

   public SFTPv3FileHandle openFileRO(String fileName) throws IOException {
      return openFile(fileName, 1, null);
   }

   public SFTPv3FileHandle openFileRW(String fileName) throws IOException {
      return openFile(fileName, 3, null);
   }

   public SFTPv3FileHandle openFileRWAppend(String fileName) throws IOException {
      return openFile(fileName, 7, null);
   }

   public SFTPv3FileHandle openFileWAppend(String fileName) throws IOException {
      return openFile(fileName, 6, null);
   }

   public SFTPv3FileHandle createFile(String fileName) throws IOException {
      return createFile(fileName, null);
   }

   public SFTPv3FileHandle createFile(String fileName, SFTPv3FileAttributes attr) throws IOException {
      return openFile(fileName, 11, attr);
   }

   public SFTPv3FileHandle createFileTruncate(String fileName) throws IOException {
      return createFileTruncate(fileName, null);
   }

   public SFTPv3FileHandle createFileTruncate(String fileName, SFTPv3FileAttributes attr) throws IOException {
      return openFile(fileName, 26, attr);
   }

   private byte[] createAttrs(SFTPv3FileAttributes attr) {
      TypesWriter tw = new TypesWriter();
      int attrFlags = 0;
      if (attr == null) {
         tw.writeUINT32(0);
      } else {
         if (attr.size != null)
            attrFlags |= 0x1;
         if (attr.uid != null && attr.gid != null)
            attrFlags |= 0x2;
         if (attr.permissions != null)
            attrFlags |= 0x4;
         if (attr.atime != null && attr.mtime != null)
            attrFlags |= 0x8;
         tw.writeUINT32(attrFlags);
         if (attr.size != null)
            tw.writeUINT64(attr.size.longValue());
         if (attr.uid != null && attr.gid != null) {
            tw.writeUINT32(attr.uid.intValue());
            tw.writeUINT32(attr.gid.intValue());
         }
         if (attr.permissions != null)
            tw.writeUINT32(attr.permissions.intValue());
         if (attr.atime != null && attr.mtime != null) {
            tw.writeUINT32(attr.atime.intValue());
            tw.writeUINT32(attr.mtime.intValue());
         }
      }
      return tw.getBytes();
   }

   public SFTPv3FileHandle openFile(String fileName, int flags, SFTPv3FileAttributes attr) throws IOException {
      int req_id = generateNextRequestID();
      TypesWriter tw = new TypesWriter();
      tw.writeString(fileName, this.charsetName);
      tw.writeUINT32(flags);
      tw.writeBytes(createAttrs(attr));
      log.debug("Sending SSH_FXP_OPEN...");
      sendMessage(3, req_id, tw.getBytes());
      byte[] resp = receiveMessage(34000);
      TypesReader tr = new TypesReader(resp);
      int t = tr.readByte();
      this.listener.read(Packet.forName(t));
      int rep_id = tr.readUINT32();
      if (rep_id != req_id)
         throw new RequestMismatchException();
      if (t == 102) {
         log.debug("Got SSH_FXP_HANDLE.");
         return new SFTPv3FileHandle(this, tr.readByteString());
      }
      if (t != 101)
         throw new PacketTypeException(t);
      int errorCode = tr.readUINT32();
      String errorMessage = tr.readString();
      this.listener.read(errorMessage);
      throw new SFTPException(errorMessage, errorCode);
   }

   private static class OutstandingReadRequest {
      int req_id;

      long serverOffset;

      int len;

      int dstOffset;

      byte[] buffer;

      private OutstandingReadRequest() {}
   }

   private void sendReadRequest(int id, SFTPv3FileHandle handle, long offset, int len) throws IOException {
      TypesWriter tw = new TypesWriter();
      tw.writeString(handle.fileHandle, 0, handle.fileHandle.length);
      tw.writeUINT64(offset);
      tw.writeUINT32(len);
      log.debug("Sending SSH_FXP_READ (" + id + ") " + offset + "/" + len);
      sendMessage(5, id, tw.getBytes());
   }

   public SFTPv3Client(Connection conn, PacketListener listener) throws IOException {
      this.parallelism = 64;
      this
              .pendingReadQueue = new HashMap<>();
      this
              .pendingStatusQueue = new HashMap<>();
      if (conn == null)
         throw new IllegalArgumentException("Cannot accept null argument!");
      this.listener = listener;
      log.debug("Opening session and starting SFTP subsystem.");
      this.sess = conn.openSession();
      this.sess.startSubSystem("sftp");
      this.is = this.sess.getStdout();
      this.os = new BufferedOutputStream(this.sess.getStdin(), 2048);
      if (this.is == null)
         throw new IOException("There is a problem with the streams of the underlying channel.");
      init();
   }

   public void setRequestParallelism(int parallelism) {
      this.parallelism = Math.min(parallelism, 64);
   }

   public int read(SFTPv3FileHandle handle, long fileOffset, byte[] dst, int dstoff, int len) throws IOException {
      int code;
      String msg;
      boolean errorOccured = false;
      checkHandleValidAndOpen(handle);
      int remaining = len * this.parallelism;
      long serverOffset = fileOffset;
      for (OutstandingReadRequest r : this.pendingReadQueue.values()) {
         serverOffset += r.len;
      }
      do {
         if (this.pendingReadQueue.size() != 0 || !errorOccured) {
            while (this.pendingReadQueue.size() < this.parallelism && !errorOccured) {
               OutstandingReadRequest req = new OutstandingReadRequest();
               req.req_id = generateNextRequestID();
               req.serverOffset = serverOffset;
               req.len = remaining > len ? len : remaining;
               req.buffer = dst;
               req.dstOffset = dstoff;
               serverOffset += req.len;
               remaining -= req.len;
               sendReadRequest(req.req_id, handle, req.serverOffset, req.len);
               this.pendingReadQueue.put(Integer.valueOf(req.req_id), req);
            }
            if (this.pendingReadQueue.size() != 0) {
               byte[] resp = receiveMessage(34000);
               TypesReader tr = new TypesReader(resp);
               int t = tr.readByte();
               this.listener.read(Packet.forName(t));
               OutstandingReadRequest req2 = this.pendingReadQueue.remove(Integer.valueOf(tr.readUINT32()));
               if (req2 == null) {
                  throw new RequestMismatchException();
               }
               if (t == 101) {
                  code = tr.readUINT32();
                  msg = tr.readString();
                  this.listener.read(msg);
                  if (log.isDebugEnabled()) {
                     String[] desc = ErrorCodes.getDescription(code);
                     log.debug("Got SSH_FXP_STATUS (" + req2.req_id + ") (" + (desc != null ? desc[0] : "UNKNOWN") + ")");
                  }
                  errorOccured = true;
               } else {
                  if (t == 103) {
                     int readLen = tr.readUINT32();
                     if (readLen < 0 || readLen > req2.len) {
                        throw new IOException("The server sent an invalid length field in a SSH_FXP_DATA packet.");
                     }
                     if (log.isDebugEnabled()) {
                        log.debug("Got SSH_FXP_DATA (" + req2.req_id + ") " + req2.serverOffset + "/" + readLen + " (requested: " + req2.len + ")");
                     }
                     tr.readBytes(req2.buffer, req2.dstOffset, readLen);
                     if (readLen < req2.len) {
                        req2.req_id = generateNextRequestID();
                        req2.serverOffset += readLen;
                        req2.len -= readLen;
                        log.debug("Requesting again: " + req2.serverOffset + "/" + req2.len);
                        sendReadRequest(req2.req_id, handle, req2.serverOffset, req2.len);
                        this.pendingReadQueue.put(Integer.valueOf(req2.req_id), req2);
                     }
                     return readLen;
                  }
                  throw new PacketTypeException(t);
               }
            }
         }
         throw new SFTPException("No EOF reached", -1);
      } while (!this.pendingReadQueue.isEmpty());
   }

   private static class OutstandingStatusRequest {
      int req_id;

      private OutstandingStatusRequest() {}
   }

   public void write(SFTPv3FileHandle handle, long fileOffset, byte[] src, int srcoff, int len) throws IOException {
      checkHandleValidAndOpen(handle);
      while (len > 0) {
         int writeRequestLen = len;
         if (writeRequestLen > 32768)
            writeRequestLen = 32768;
         OutstandingStatusRequest req = new OutstandingStatusRequest();
         req.req_id = generateNextRequestID();
         TypesWriter tw = new TypesWriter();
         tw.writeString(handle.fileHandle, 0, handle.fileHandle.length);
         tw.writeUINT64(fileOffset);
         tw.writeString(src, srcoff, writeRequestLen);
         log.debug("Sending SSH_FXP_WRITE...");
         sendMessage(6, req.req_id, tw.getBytes());
         this.pendingStatusQueue.put(Integer.valueOf(req.req_id), req);
         while (this.pendingStatusQueue.size() >= this.parallelism)
            readStatus();
         fileOffset += writeRequestLen;
         srcoff += writeRequestLen;
         len -= writeRequestLen;
      }
   }

   private void readStatus() throws IOException {
      byte[] resp = receiveMessage(34000);
      TypesReader tr = new TypesReader(resp);
      int t = tr.readByte();
      this.listener.read(Packet.forName(t));
      OutstandingStatusRequest status = this.pendingStatusQueue.remove(Integer.valueOf(tr.readUINT32()));
      if (status == null)
         throw new RequestMismatchException();
      if (t == 101) {
         int code = tr.readUINT32();
         if (log.isDebugEnabled()) {
            String[] desc = ErrorCodes.getDescription(code);
            log.debug("Got SSH_FXP_STATUS (" + status.req_id + ") (" + ((desc != null) ? desc[0] : "UNKNOWN") + ")");
         }
         if (code == 0)
            return;
         String msg = tr.readString();
         this.listener.read(msg);
         throw new SFTPException(msg, code);
      }
      throw new PacketTypeException(t);
   }

   private void readPendingReadStatus() throws IOException {
      byte[] resp = receiveMessage(34000);
      TypesReader tr = new TypesReader(resp);
      int t = tr.readByte();
      this.listener.read(Packet.forName(t));
      OutstandingReadRequest status = this.pendingReadQueue.remove(Integer.valueOf(tr.readUINT32()));
      if (status == null)
         throw new RequestMismatchException();
      if (t == 101) {
         int code = tr.readUINT32();
         if (log.isDebugEnabled()) {
            String[] desc = ErrorCodes.getDescription(code);
            log.debug("Got SSH_FXP_STATUS (" + status.req_id + ") (" + ((desc != null) ? desc[0] : "UNKNOWN") + ")");
         }
         if (code == 0)
            return;
         if (code == 1)
            return;
         String msg = tr.readString();
         this.listener.read(msg);
         throw new SFTPException(msg, code);
      }
      throw new PacketTypeException(t);
   }

   public void closeFile(SFTPv3FileHandle handle) throws IOException {
      try {
         while (!this.pendingReadQueue.isEmpty())
            readPendingReadStatus();
         while (!this.pendingStatusQueue.isEmpty())
            readStatus();
         if (!handle.isClosed)
            closeHandle(handle.fileHandle);
      } finally {
         handle.isClosed = true;
      }
   }
}
