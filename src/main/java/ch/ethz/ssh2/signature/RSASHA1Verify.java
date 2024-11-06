package ch.ethz.ssh2.signature;

import ch.ethz.ssh2.crypto.SimpleDERReader;
import ch.ethz.ssh2.crypto.digest.SHA1;
import ch.ethz.ssh2.log.Logger;
import ch.ethz.ssh2.packets.TypesReader;
import ch.ethz.ssh2.packets.TypesWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class RSASHA1Verify {
   private static final Logger log = Logger.getLogger(RSASHA1Verify.class);

   public static RSAPublicKey decodeSSHRSAPublicKey(byte[] key) throws IOException {
      TypesReader tr = new TypesReader(key);
      String key_format = tr.readString();
      if (!key_format.equals("ssh-rsa")) {
         throw new IllegalArgumentException("This is not a ssh-rsa public key");
      } else {
         BigInteger e = tr.readMPINT();
         BigInteger n = tr.readMPINT();
         if (tr.remain() != 0) {
            throw new IOException("Padding in RSA public key!");
         } else {
            return new RSAPublicKey(e, n);
         }
      }
   }

   public static byte[] encodeSSHRSAPublicKey(RSAPublicKey pk) throws IOException {
      TypesWriter tw = new TypesWriter();
      tw.writeString("ssh-rsa");
      tw.writeMPInt(pk.getE());
      tw.writeMPInt(pk.getN());
      return tw.getBytes();
   }

   public static RSASignature decodeSSHRSASignature(byte[] sig) throws IOException {
      TypesReader tr = new TypesReader(sig);
      String sig_format = tr.readString();
      if (!sig_format.equals("ssh-rsa") && !sig_format.equals("rsa-sha2-256")) {
         throw new IOException("Peer sent wrong signature format");
      } else {
         byte[] s = tr.readByteString();
         if (s.length == 0) {
            throw new IOException("Error in RSA signature, S is empty.");
         } else {
            if (log.isDebugEnabled()) {
               log.debug("Decoding ssh-rsa signature string (length: " + s.length + ")");
            }

            if (tr.remain() != 0) {
               throw new IOException("Padding in RSA signature!");
            } else {
               return new RSASignature(new BigInteger(1, s));
            }
         }
      }
   }

   public static byte[] encodeSSHRSASignature(RSASignature sig) throws IOException {
      TypesWriter tw = new TypesWriter();
      tw.writeString("ssh-rsa");
      byte[] s = sig.getS().toByteArray();
      if (s.length > 1 && s[0] == 0) {
         tw.writeString(s, 1, s.length - 1);
      } else {
         tw.writeString(s, 0, s.length);
      }

      return tw.getBytes();
   }

   public static RSASignature generateSignature(byte[] message, RSAPrivateKey pk) throws IOException {
      SHA1 md = new SHA1();
      md.update(message);
      byte[] sha_message = new byte[md.getDigestLength()];
      md.digest(sha_message);
      byte[] der_header = new byte[]{48, 33, 48, 9, 6, 5, 43, 14, 3, 2, 26, 5, 0, 4, 20};
      int rsa_block_len = (pk.getN().bitLength() + 7) / 8;
      int num_pad = rsa_block_len - (2 + der_header.length + sha_message.length) - 1;
      if (num_pad < 8) {
         throw new IOException("Cannot sign with RSA, message too long");
      } else {
         byte[] sig = new byte[der_header.length + sha_message.length + 2 + num_pad];
         sig[0] = 1;

         for(int i = 0; i < num_pad; ++i) {
            sig[i + 1] = -1;
         }

         sig[num_pad + 1] = 0;
         System.arraycopy(der_header, 0, sig, 2 + num_pad, der_header.length);
         System.arraycopy(sha_message, 0, sig, 2 + num_pad + der_header.length, sha_message.length);
         BigInteger m = new BigInteger(1, sig);
         BigInteger s = m.modPow(pk.getD(), pk.getN());
         return new RSASignature(s);
      }
   }

   public static boolean verifySignature(byte[] message, RSASignature ds, RSAPublicKey dpk, String hashAlgorithm) throws IOException, NoSuchAlgorithmException {
      MessageDigest md = MessageDigest.getInstance(hashAlgorithm);
      byte[] sha_message = md.digest(message);

      try {
         BigInteger n = dpk.getN();
         BigInteger e = dpk.getE();
         BigInteger s = ds.getS();
         if (n.compareTo(s) <= 0) {
            log.warning("ssh-rsa signature: n.compareTo(s) <= 0");
            return false;
         } else {
            int rsa_block_len = (n.bitLength() + 7) / 8;
            if (rsa_block_len < 1) {
               log.warning("ssh-rsa signature: rsa_block_len < 1");
               return false;
            } else {
               byte[] v = s.modPow(e, n).toByteArray();
               int startpos = 0;
               if (v.length > 0 && v[0] == 0) {
                  ++startpos;
               }

               if (v.length - startpos != rsa_block_len - 1) {
                  log.warning("ssh-rsa signature: (v.length - startpos) != (rsa_block_len - 1)");
                  return false;
               } else if (v[startpos] != 1) {
                  log.warning("ssh-rsa signature: v[startpos] != 0x01");
                  return false;
               } else {
                  for(int pos = startpos + 1; pos < v.length; ++pos) {
                     if (v[pos] == 0) {
                        int num_pad = pos - (startpos + 1);
                        if (num_pad < 8) {
                           log.warning("ssh-rsa signature: num_pad < 8");
                           return false;
                        }

                        ++pos;
                        if (pos >= v.length) {
                           log.warning("ssh-rsa signature: pos >= v.length");
                           return false;
                        }

                        SimpleDERReader dr = new SimpleDERReader(v, pos, v.length - pos);
                        byte[] seq = dr.readSequenceAsByteArray();
                        if (dr.available() != 0) {
                           log.warning("ssh-rsa signature: dr.available() != 0");
                           return false;
                        }

                        dr.resetInput(seq);
                        byte[] digestAlgorithm = dr.readSequenceAsByteArray();
                        byte[] digestAlgorithm_sha1 = new byte[]{6, 5, 43, 14, 3, 2, 26, 5, 0};
                        byte[] digestAlgorithm_sha256 = new byte[]{6, 9, 96, -122, 72, 1, 101, 3, 4, 2, 1, 5, 0};
                        byte[] digestAlgorithm_sha512 = new byte[]{6, 9, 96, -122, 72, 1, 101, 3, 4, 2, 3, 5, 0};
                        byte[] digestAlgorithmToCheck = null;
                        if ("SHA-1".equalsIgnoreCase(hashAlgorithm)) {
                           digestAlgorithmToCheck = digestAlgorithm_sha1;
                        } else if ("SHA-256".equalsIgnoreCase(hashAlgorithm)) {
                           digestAlgorithmToCheck = digestAlgorithm_sha256;
                        } else if ("SHA-512".equalsIgnoreCase(hashAlgorithm)) {
                           digestAlgorithmToCheck = digestAlgorithm_sha512;
                        }

                        if (digestAlgorithmToCheck != null && MessageDigest.isEqual(digestAlgorithm, digestAlgorithmToCheck)) {
                           byte[] digest = dr.readOctetString();
                           if (dr.available() != 0) {
                              log.warning("ssh-rsa signature: dr.available() != 0 (II)");
                              return false;
                           }

                           if (!MessageDigest.isEqual(sha_message, digest)) {
                              log.warning("ssh-rsa signature: sha_message != digest");
                              return false;
                           }

                           return true;
                        }

                        log.warning("ssh-rsa signature: incorrect digest algorithm");
                        return false;
                     }

                     if (v[pos] != -1) {
                        log.warning("ssh-rsa signature: v[pos] != (byte) 0xff");
                        return false;
                     }
                  }

                  log.warning("ssh-rsa signature: pos >= v.length");
                  return false;
               }
            }
         }
      } catch (Exception var22) {
         log.warning("Exception during signature verification: " + var22.getMessage());
         return false;
      }
   }
}
