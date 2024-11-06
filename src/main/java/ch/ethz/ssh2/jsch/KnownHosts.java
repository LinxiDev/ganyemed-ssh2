package ch.ethz.ssh2.jsch;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Vector;

class KnownHosts implements HostKeyRepository {
   private String known_hosts = null;

   private Vector<HostKey> pool = null;

   MAC hmacsha1;

   KnownHosts() {
      getHMACSHA1();
      this.pool = new Vector<>();
   }

   void setKnownHosts(String filename) throws JSchException {
      try {
         this.known_hosts = filename;
         InputStream fis = new FileInputStream(Util.checkTilde(filename));
         setKnownHosts(fis);
      } catch (FileNotFoundException fileNotFoundException) {}
   }

   void setKnownHosts(InputStream input) throws JSchException {
      // Byte code:
      //   0: aload_0
      //   1: getfield pool : Ljava/util/Vector;
      //   4: invokevirtual removeAllElements : ()V
      //   7: new java/lang/StringBuilder
      //   10: dup
      //   11: invokespecial <init> : ()V
      //   14: astore_2
      //   15: iconst_0
      //   16: istore #5
      //   18: aconst_null
      //   19: astore #6
      //   21: aconst_null
      //   22: astore #7
      //   24: aload_1
      //   25: astore #8
      //   27: aconst_null
      //   28: astore #10
      //   30: sipush #1024
      //   33: newarray byte
      //   35: astore #12
      //   37: iconst_0
      //   38: istore #13
      //   40: iconst_0
      //   41: istore #13
      //   43: aload #8
      //   45: invokevirtual read : ()I
      //   48: istore #4
      //   50: iload #4
      //   52: iconst_m1
      //   53: if_icmpne -> 64
      //   56: iload #13
      //   58: ifne -> 142
      //   61: goto -> 822
      //   64: iload #4
      //   66: bipush #13
      //   68: if_icmpne -> 74
      //   71: goto -> 43
      //   74: iload #4
      //   76: bipush #10
      //   78: if_icmpne -> 84
      //   81: goto -> 142
      //   84: aload #12
      //   86: arraylength
      //   87: iload #13
      //   89: if_icmpgt -> 128
      //   92: iload #13
      //   94: sipush #10240
      //   97: if_icmple -> 103
      //   100: goto -> 142
      //   103: aload #12
      //   105: arraylength
      //   106: iconst_2
      //   107: imul
      //   108: newarray byte
      //   110: astore #14
      //   112: aload #12
      //   114: iconst_0
      //   115: aload #14
      //   117: iconst_0
      //   118: aload #12
      //   120: arraylength
      //   121: invokestatic arraycopy : (Ljava/lang/Object;ILjava/lang/Object;II)V
      //   124: aload #14
      //   126: astore #12
      //   128: aload #12
      //   130: iload #13
      //   132: iinc #13, 1
      //   135: iload #4
      //   137: i2b
      //   138: bastore
      //   139: goto -> 43
      //   142: iconst_0
      //   143: istore #4
      //   145: goto -> 193
      //   148: aload #12
      //   150: iload #4
      //   152: baload
      //   153: istore_3
      //   154: iload_3
      //   155: bipush #32
      //   157: if_icmpeq -> 166
      //   160: iload_3
      //   161: bipush #9
      //   163: if_icmpne -> 172
      //   166: iinc #4, 1
      //   169: goto -> 193
      //   172: iload_3
      //   173: bipush #35
      //   175: if_icmpne -> 200
      //   178: aload_0
      //   179: aload #12
      //   181: iconst_0
      //   182: iload #13
      //   184: invokestatic byte2str : ([BII)Ljava/lang/String;
      //   187: invokespecial addInvalidLine : (Ljava/lang/String;)V
      //   190: goto -> 40
      //   193: iload #4
      //   195: iload #13
      //   197: if_icmplt -> 148
      //   200: iload #4
      //   202: iload #13
      //   204: if_icmplt -> 222
      //   207: aload_0
      //   208: aload #12
      //   210: iconst_0
      //   211: iload #13
      //   213: invokestatic byte2str : ([BII)Ljava/lang/String;
      //   216: invokespecial addInvalidLine : (Ljava/lang/String;)V
      //   219: goto -> 40
      //   222: aload_2
      //   223: iconst_0
      //   224: invokevirtual setLength : (I)V
      //   227: goto -> 261
      //   230: aload #12
      //   232: iload #4
      //   234: iinc #4, 1
      //   237: baload
      //   238: istore_3
      //   239: iload_3
      //   240: bipush #32
      //   242: if_icmpeq -> 268
      //   245: iload_3
      //   246: bipush #9
      //   248: if_icmpne -> 254
      //   251: goto -> 268
      //   254: aload_2
      //   255: iload_3
      //   256: i2c
      //   257: invokevirtual append : (C)Ljava/lang/StringBuilder;
      //   260: pop
      //   261: iload #4
      //   263: iload #13
      //   265: if_icmplt -> 230
      //   268: aload_2
      //   269: invokevirtual toString : ()Ljava/lang/String;
      //   272: astore #9
      //   274: iload #4
      //   276: iload #13
      //   278: if_icmpge -> 289
      //   281: aload #9
      //   283: invokevirtual length : ()I
      //   286: ifne -> 325
      //   289: aload_0
      //   290: aload #12
      //   292: iconst_0
      //   293: iload #13
      //   295: invokestatic byte2str : ([BII)Ljava/lang/String;
      //   298: invokespecial addInvalidLine : (Ljava/lang/String;)V
      //   301: goto -> 40
      //   304: aload #12
      //   306: iload #4
      //   308: baload
      //   309: istore_3
      //   310: iload_3
      //   311: bipush #32
      //   313: if_icmpeq -> 322
      //   316: iload_3
      //   317: bipush #9
      //   319: if_icmpne -> 332
      //   322: iinc #4, 1
      //   325: iload #4
      //   327: iload #13
      //   329: if_icmplt -> 304
      //   332: ldc ''
      //   334: astore #14
      //   336: aload #9
      //   338: iconst_0
      //   339: invokevirtual charAt : (I)C
      //   342: bipush #64
      //   344: if_icmpne -> 461
      //   347: aload #9
      //   349: astore #14
      //   351: aload_2
      //   352: iconst_0
      //   353: invokevirtual setLength : (I)V
      //   356: goto -> 390
      //   359: aload #12
      //   361: iload #4
      //   363: iinc #4, 1
      //   366: baload
      //   367: istore_3
      //   368: iload_3
      //   369: bipush #32
      //   371: if_icmpeq -> 397
      //   374: iload_3
      //   375: bipush #9
      //   377: if_icmpne -> 383
      //   380: goto -> 397
      //   383: aload_2
      //   384: iload_3
      //   385: i2c
      //   386: invokevirtual append : (C)Ljava/lang/StringBuilder;
      //   389: pop
      //   390: iload #4
      //   392: iload #13
      //   394: if_icmplt -> 359
      //   397: aload_2
      //   398: invokevirtual toString : ()Ljava/lang/String;
      //   401: astore #9
      //   403: iload #4
      //   405: iload #13
      //   407: if_icmpge -> 418
      //   410: aload #9
      //   412: invokevirtual length : ()I
      //   415: ifne -> 454
      //   418: aload_0
      //   419: aload #12
      //   421: iconst_0
      //   422: iload #13
      //   424: invokestatic byte2str : ([BII)Ljava/lang/String;
      //   427: invokespecial addInvalidLine : (Ljava/lang/String;)V
      //   430: goto -> 40
      //   433: aload #12
      //   435: iload #4
      //   437: baload
      //   438: istore_3
      //   439: iload_3
      //   440: bipush #32
      //   442: if_icmpeq -> 451
      //   445: iload_3
      //   446: bipush #9
      //   448: if_icmpne -> 461
      //   451: iinc #4, 1
      //   454: iload #4
      //   456: iload #13
      //   458: if_icmplt -> 433
      //   461: aload_2
      //   462: iconst_0
      //   463: invokevirtual setLength : (I)V
      //   466: iconst_m1
      //   467: istore #11
      //   469: goto -> 503
      //   472: aload #12
      //   474: iload #4
      //   476: iinc #4, 1
      //   479: baload
      //   480: istore_3
      //   481: iload_3
      //   482: bipush #32
      //   484: if_icmpeq -> 510
      //   487: iload_3
      //   488: bipush #9
      //   490: if_icmpne -> 496
      //   493: goto -> 510
      //   496: aload_2
      //   497: iload_3
      //   498: i2c
      //   499: invokevirtual append : (C)Ljava/lang/StringBuilder;
      //   502: pop
      //   503: iload #4
      //   505: iload #13
      //   507: if_icmplt -> 472
      //   510: aload_2
      //   511: invokevirtual toString : ()Ljava/lang/String;
      //   514: astore #15
      //   516: aload #15
      //   518: invokestatic name2type : (Ljava/lang/String;)I
      //   521: iconst_m1
      //   522: if_icmpeq -> 535
      //   525: aload #15
      //   527: invokestatic name2type : (Ljava/lang/String;)I
      //   530: istore #11
      //   532: goto -> 539
      //   535: iload #13
      //   537: istore #4
      //   539: iload #4
      //   541: iload #13
      //   543: if_icmplt -> 582
      //   546: aload_0
      //   547: aload #12
      //   549: iconst_0
      //   550: iload #13
      //   552: invokestatic byte2str : ([BII)Ljava/lang/String;
      //   555: invokespecial addInvalidLine : (Ljava/lang/String;)V
      //   558: goto -> 40
      //   561: aload #12
      //   563: iload #4
      //   565: baload
      //   566: istore_3
      //   567: iload_3
      //   568: bipush #32
      //   570: if_icmpeq -> 579
      //   573: iload_3
      //   574: bipush #9
      //   576: if_icmpne -> 589
      //   579: iinc #4, 1
      //   582: iload #4
      //   584: iload #13
      //   586: if_icmplt -> 561
      //   589: aload_2
      //   590: iconst_0
      //   591: invokevirtual setLength : (I)V
      //   594: goto -> 646
      //   597: aload #12
      //   599: iload #4
      //   601: iinc #4, 1
      //   604: baload
      //   605: istore_3
      //   606: iload_3
      //   607: bipush #13
      //   609: if_icmpne -> 615
      //   612: goto -> 646
      //   615: iload_3
      //   616: bipush #10
      //   618: if_icmpne -> 624
      //   621: goto -> 653
      //   624: iload_3
      //   625: bipush #32
      //   627: if_icmpeq -> 653
      //   630: iload_3
      //   631: bipush #9
      //   633: if_icmpne -> 639
      //   636: goto -> 653
      //   639: aload_2
      //   640: iload_3
      //   641: i2c
      //   642: invokevirtual append : (C)Ljava/lang/StringBuilder;
      //   645: pop
      //   646: iload #4
      //   648: iload #13
      //   650: if_icmplt -> 597
      //   653: aload_2
      //   654: invokevirtual toString : ()Ljava/lang/String;
      //   657: astore #10
      //   659: aload #10
      //   661: invokevirtual length : ()I
      //   664: ifne -> 703
      //   667: aload_0
      //   668: aload #12
      //   670: iconst_0
      //   671: iload #13
      //   673: invokestatic byte2str : ([BII)Ljava/lang/String;
      //   676: invokespecial addInvalidLine : (Ljava/lang/String;)V
      //   679: goto -> 40
      //   682: aload #12
      //   684: iload #4
      //   686: baload
      //   687: istore_3
      //   688: iload_3
      //   689: bipush #32
      //   691: if_icmpeq -> 700
      //   694: iload_3
      //   695: bipush #9
      //   697: if_icmpne -> 710
      //   700: iinc #4, 1
      //   703: iload #4
      //   705: iload #13
      //   707: if_icmplt -> 682
      //   710: aconst_null
      //   711: astore #16
      //   713: iload #4
      //   715: iload #13
      //   717: if_icmpge -> 775
      //   720: aload_2
      //   721: iconst_0
      //   722: invokevirtual setLength : (I)V
      //   725: goto -> 762
      //   728: aload #12
      //   730: iload #4
      //   732: iinc #4, 1
      //   735: baload
      //   736: istore_3
      //   737: iload_3
      //   738: bipush #13
      //   740: if_icmpne -> 746
      //   743: goto -> 762
      //   746: iload_3
      //   747: bipush #10
      //   749: if_icmpne -> 755
      //   752: goto -> 769
      //   755: aload_2
      //   756: iload_3
      //   757: i2c
      //   758: invokevirtual append : (C)Ljava/lang/StringBuilder;
      //   761: pop
      //   762: iload #4
      //   764: iload #13
      //   766: if_icmplt -> 728
      //   769: aload_2
      //   770: invokevirtual toString : ()Ljava/lang/String;
      //   773: astore #16
      //   775: aconst_null
      //   776: astore #17
      //   778: new ch/ethz/ssh2/jsch/KnownHosts$HashedHostKey
      //   781: dup
      //   782: aload_0
      //   783: aload #14
      //   785: aload #9
      //   787: iload #11
      //   789: aload #10
      //   791: invokestatic str2byte : (Ljava/lang/String;)[B
      //   794: iconst_0
      //   795: aload #10
      //   797: invokevirtual length : ()I
      //   800: invokestatic fromBase64 : ([BII)[B
      //   803: aload #16
      //   805: invokespecial <init> : (Lch/ethz/ssh2/jsch/KnownHosts;Ljava/lang/String;Ljava/lang/String;I[BLjava/lang/String;)V
      //   808: astore #17
      //   810: aload_0
      //   811: getfield pool : Ljava/util/Vector;
      //   814: aload #17
      //   816: invokevirtual addElement : (Ljava/lang/Object;)V
      //   819: goto -> 40
      //   822: iload #5
      //   824: ifeq -> 837
      //   827: new ch/ethz/ssh2/jsch/JSchException
      //   830: dup
      //   831: ldc 'KnownHosts: invalid format'
      //   833: invokespecial <init> : (Ljava/lang/String;)V
      //   836: athrow
      //   837: aload #8
      //   839: ifnull -> 927
      //   842: aload #8
      //   844: invokevirtual close : ()V
      //   847: goto -> 927
      //   850: astore #6
      //   852: aload #8
      //   854: ifnull -> 862
      //   857: aload #8
      //   859: invokevirtual close : ()V
      //   862: aload #6
      //   864: athrow
      //   865: astore #7
      //   867: aload #6
      //   869: ifnonnull -> 879
      //   872: aload #7
      //   874: astore #6
      //   876: goto -> 893
      //   879: aload #6
      //   881: aload #7
      //   883: if_acmpeq -> 893
      //   886: aload #6
      //   888: aload #7
      //   890: invokevirtual addSuppressed : (Ljava/lang/Throwable;)V
      //   893: aload #6
      //   895: athrow
      //   896: astore #6
      //   898: aload #6
      //   900: instanceof ch/ethz/ssh2/jsch/JSchException
      //   903: ifeq -> 912
      //   906: aload #6
      //   908: checkcast ch/ethz/ssh2/jsch/JSchException
      //   911: athrow
      //   912: new ch/ethz/ssh2/jsch/JSchException
      //   915: dup
      //   916: aload #6
      //   918: invokevirtual toString : ()Ljava/lang/String;
      //   921: aload #6
      //   923: invokespecial <init> : (Ljava/lang/String;Ljava/lang/Throwable;)V
      //   926: athrow
      //   927: return
      // Line number table:
      //   Java source line number -> byte code offset
      //   #65	-> 0
      //   #66	-> 7
      //   #69	-> 15
      //   #70	-> 18
      //   #72	-> 27
      //   #74	-> 30
      //   #75	-> 37
      //   #77	-> 40
      //   #79	-> 43
      //   #80	-> 50
      //   #81	-> 56
      //   #82	-> 61
      //   #86	-> 64
      //   #87	-> 71
      //   #89	-> 74
      //   #90	-> 81
      //   #92	-> 84
      //   #93	-> 92
      //   #94	-> 100
      //   #95	-> 103
      //   #96	-> 112
      //   #97	-> 124
      //   #99	-> 128
      //   #78	-> 139
      //   #102	-> 142
      //   #103	-> 145
      //   #104	-> 148
      //   #105	-> 154
      //   #106	-> 166
      //   #107	-> 169
      //   #109	-> 172
      //   #110	-> 178
      //   #111	-> 190
      //   #103	-> 193
      //   #115	-> 200
      //   #116	-> 207
      //   #117	-> 219
      //   #120	-> 222
      //   #121	-> 227
      //   #122	-> 230
      //   #123	-> 239
      //   #124	-> 251
      //   #126	-> 254
      //   #121	-> 261
      //   #128	-> 268
      //   #129	-> 274
      //   #130	-> 289
      //   #131	-> 301
      //   #135	-> 304
      //   #136	-> 310
      //   #137	-> 322
      //   #134	-> 325
      //   #143	-> 332
      //   #144	-> 336
      //   #145	-> 347
      //   #147	-> 351
      //   #148	-> 356
      //   #149	-> 359
      //   #150	-> 368
      //   #151	-> 380
      //   #153	-> 383
      //   #148	-> 390
      //   #155	-> 397
      //   #156	-> 403
      //   #157	-> 418
      //   #158	-> 430
      //   #162	-> 433
      //   #163	-> 439
      //   #164	-> 451
      //   #161	-> 454
      //   #171	-> 461
      //   #172	-> 466
      //   #173	-> 469
      //   #174	-> 472
      //   #175	-> 481
      //   #176	-> 493
      //   #178	-> 496
      //   #173	-> 503
      //   #180	-> 510
      //   #181	-> 516
      //   #182	-> 525
      //   #183	-> 532
      //   #184	-> 535
      //   #186	-> 539
      //   #187	-> 546
      //   #188	-> 558
      //   #192	-> 561
      //   #193	-> 567
      //   #194	-> 579
      //   #191	-> 582
      //   #200	-> 589
      //   #201	-> 594
      //   #202	-> 597
      //   #203	-> 606
      //   #204	-> 612
      //   #206	-> 615
      //   #207	-> 621
      //   #209	-> 624
      //   #210	-> 636
      //   #212	-> 639
      //   #201	-> 646
      //   #214	-> 653
      //   #215	-> 659
      //   #216	-> 667
      //   #217	-> 679
      //   #221	-> 682
      //   #222	-> 688
      //   #223	-> 700
      //   #220	-> 703
      //   #236	-> 710
      //   #237	-> 713
      //   #238	-> 720
      //   #239	-> 725
      //   #240	-> 728
      //   #241	-> 737
      //   #242	-> 743
      //   #244	-> 746
      //   #245	-> 752
      //   #247	-> 755
      //   #239	-> 762
      //   #249	-> 769
      //   #255	-> 775
      //   #256	-> 778
      //   #257	-> 789
      //   #256	-> 805
      //   #258	-> 810
      //   #76	-> 819
      //   #260	-> 822
      //   #261	-> 827
      //   #263	-> 837
      //   #264	-> 898
      //   #265	-> 906
      //   #266	-> 912
      //   #268	-> 927
      // Local variable table:
      //   start	length	slot	name	descriptor
      //   0	928	0	this	Lch/ethz/ssh2/jsch/KnownHosts;
      //   0	928	1	input	Ljava/io/InputStream;
      //   15	913	2	sb	Ljava/lang/StringBuilder;
      //   154	39	3	i	B
      //   239	22	3	i	B
      //   310	15	3	i	B
      //   368	22	3	i	B
      //   439	15	3	i	B
      //   481	22	3	i	B
      //   567	15	3	i	B
      //   606	40	3	i	B
      //   688	15	3	i	B
      //   737	25	3	i	B
      //   50	89	4	j	I
      //   142	677	4	j	I
      //   822	28	4	j	I
      //   927	1	4	j	I
      //   18	910	5	error	Z
      //   27	835	8	fis	Ljava/io/InputStream;
      //   274	545	9	host	Ljava/lang/String;
      //   30	807	10	key	Ljava/lang/String;
      //   469	350	11	type	I
      //   37	800	12	buf	[B
      //   40	797	13	bufl	I
      //   112	16	14	newbuf	[B
      //   336	483	14	marker	Ljava/lang/String;
      //   516	303	15	tmp	Ljava/lang/String;
      //   713	106	16	comment	Ljava/lang/String;
      //   778	41	17	hk	Lch/ethz/ssh2/jsch/HostKey;
      //   898	29	6	e	Ljava/lang/Exception;
      // Exception table:
      //   from	to	target	type
      //   18	896	896	java/lang/Exception
      //   24	865	865	finally
      //   27	837	850	finally
   }

   private void addInvalidLine(String line) throws JSchException {
      HostKey hk = new HostKey(line, -1, null);
      this.pool.addElement(hk);
   }

   String getKnownHostsFile() {
      return this.known_hosts;
   }

   public String getKnownHostsRepositoryID() {
      return this.known_hosts;
   }

   public int check(String host, byte[] key) {
      int result = 1;
      if (host == null)
         return result;
      HostKey hk = null;
      try {
         hk = new HostKey(host, 0, key);
      } catch (Exception e) {
         e.printStackTrace();
         return result;
      }
      synchronized (this.pool) {
         for (int i = 0; i < this.pool.size(); i++) {
            HostKey _hk = this.pool.elementAt(i);
            if (_hk.isMatched(host) && _hk.type == hk.type) {
               if (Util.array_equals(_hk.key, key))
                  return 0;
               result = 2;
            }
         }
      }
      if (result == 1 && host.startsWith("[") && host.indexOf("]:") > 1)
         return check(host.substring(1, host.indexOf("]:")), key);
      return result;
   }

   public HostKey[] getHostKey() {
      return getHostKey(null, null);
   }

   public HostKey[] getHostKey(String host, String type) {
      synchronized (this.pool) {
         List<HostKey> v = new ArrayList<>();
         for (int i = 0; i < this.pool.size(); i++) {
            HostKey hk = this.pool.elementAt(i);
            if (hk.type != -1)
               if (host == null || (hk.isMatched(host) && (type == null || hk.getType().equals(type))))
                  v.add(hk);
         }
         HostKey[] foo = new HostKey[v.size()];
         for (int j = 0; j < v.size(); j++)
            foo[j] = v.get(j);
         if (host != null && host.startsWith("[") && host.indexOf("]:") > 1) {
            HostKey[] tmp = getHostKey(host.substring(1, host.indexOf("]:")), type);
            if (tmp.length > 0) {
               HostKey[] bar = new HostKey[foo.length + tmp.length];
               System.arraycopy(foo, 0, bar, 0, foo.length);
               System.arraycopy(tmp, 0, bar, foo.length, tmp.length);
               foo = bar;
            }
         }
         return foo;
      }
   }

   public void remove(String host, String type) {
      remove(host, type, null);
   }

   public void remove(String host, String type, byte[] key) {
      boolean sync = false;
      synchronized (this.pool) {
         for (int i = 0; i < this.pool.size(); i++) {
            HostKey hk = this.pool.elementAt(i);
            if (host == null || (hk.isMatched(host) && (type == null || (
                    hk.getType().equals(type) && (key == null || Util.array_equals(key, hk.key)))))) {
               String hosts = hk.getHost();
               if (host == null || hosts.equals(host) || (
                       hk instanceof HashedHostKey && ((HashedHostKey)hk).isHashed())) {
                  this.pool.removeElement(hk);
                  i--;
               } else {
                  hk.host = deleteSubString(hosts, host);
               }
               sync = true;
            }
         }
      }
      if (sync)
         try {
            sync();
         } catch (Exception exception) {}
   }

   void sync() throws IOException {
      if (this.known_hosts != null)
         sync(this.known_hosts);
   }

   synchronized void sync(String foo) throws IOException {
      if (foo == null)
         return;
      Exception exception1 = null, exception2 = null;
   }

   private static final byte[] space = new byte[] { 32 };

   private static final byte[] lf = Util.str2byte("\n");

   void dump(OutputStream out) {
      try {
         synchronized (this.pool) {
            for (int i = 0; i < this.pool.size(); i++) {
               HostKey hk = this.pool.elementAt(i);
               dumpHostKey(out, hk);
            }
         }
      } catch (Exception e) {
         e.printStackTrace();
      }
   }

   void dumpHostKey(OutputStream out, HostKey hk) throws IOException {
      String marker = hk.getMarker();
      String host = hk.getHost();
      String type = hk.getType();
      String comment = hk.getComment();
      if (type.equals("UNKNOWN")) {
         out.write(Util.str2byte(host));
         out.write(lf);
         return;
      }
      if (marker.length() != 0) {
         out.write(Util.str2byte(marker));
         out.write(space);
      }
      out.write(Util.str2byte(host));
      out.write(space);
      out.write(Util.str2byte(type));
      out.write(space);
      out.write(Util.str2byte(hk.getKey()));
      if (comment != null) {
         out.write(space);
         out.write(Util.str2byte(comment));
      }
      out.write(lf);
   }

   String deleteSubString(String hosts, String host) {
      int i = 0;
      int hostlen = host.length();
      int hostslen = hosts.length();
      while (i < hostslen) {
         int j = hosts.indexOf(',', i);
         if (j == -1)
            break;
         if (!host.equals(hosts.substring(i, j))) {
            i = j + 1;
            continue;
         }
         return String.valueOf(hosts.substring(0, i)) + hosts.substring(j + 1);
      }
      if (hosts.endsWith(host) && hostslen - i == hostlen)
         return hosts.substring(0, (hostlen == hostslen) ? 0 : (hostslen - hostlen - 1));
      return hosts;
   }

   MAC getHMACSHA1() throws IllegalArgumentException {
      if (this.hmacsha1 == null)
         this.hmacsha1 = createHMAC(Util.getConfig("hmac-sha1"));
      return this.hmacsha1;
   }

   MAC createHMAC(String hmacClassname) throws IllegalArgumentException {
      try {
         Class<? extends MAC> c = Class.forName(hmacClassname).asSubclass(MAC.class);
         return c.getDeclaredConstructor(new Class[0]).newInstance(new Object[0]);
      } catch (Exception e) {
         e.printStackTrace();
         throw new IllegalArgumentException("instantiation of " + hmacClassname + " lead to an error",
                 e);
      }
   }

   HostKey createHashedHostKey(String host, byte[] key) throws JSchException {
      HashedHostKey hhk = new HashedHostKey(host, key);
      hhk.hash();
      return hhk;
   }

   class HashedHostKey extends HostKey {
      private static final String HASH_MAGIC = "|1|";

      private static final String HASH_DELIM = "|";

      private boolean hashed = false;

      byte[] salt = null;

      byte[] hash = null;

      HashedHostKey(String host, byte[] key) throws JSchException {
         this(host, 0, key);
      }

      HashedHostKey(String host, int type, byte[] key) throws JSchException {
         this("", host, type, key, null);
      }

      HashedHostKey(String marker, String host, int type, byte[] key, String comment) throws JSchException {
         super(marker, host, type, key, comment);
         if (this.host.startsWith("|1|") &&
                 this.host.substring("|1|".length()).indexOf("|") > 0) {
            String data = this.host.substring("|1|".length());
            String _salt = data.substring(0, data.indexOf("|"));
            String _hash = data.substring(data.indexOf("|") + 1);
            this.salt = Util.fromBase64(Util.str2byte(_salt), 0, _salt.length());
            this.hash = Util.fromBase64(Util.str2byte(_hash), 0, _hash.length());
            int blockSize = KnownHosts.this.hmacsha1.getBlockSize();
            if (this.salt.length != blockSize || this.hash.length != blockSize) {
               this.salt = null;
               this.hash = null;
               return;
            }
            this.hashed = true;
         }
      }

      boolean isMatched(String _host) {
         if (!this.hashed)
            return super.isMatched(_host);
         try {
            synchronized (KnownHosts.this.hmacsha1) {
               KnownHosts.this.hmacsha1.init(this.salt);
               byte[] foo = Util.str2byte(_host);
               KnownHosts.this.hmacsha1.update(foo, 0, foo.length);
               byte[] bar = new byte[KnownHosts.this.hmacsha1.getBlockSize()];
               KnownHosts.this.hmacsha1.doFinal(bar, 0);
               return Util.array_equals(this.hash, bar);
            }
         } catch (Exception e) {
            e.printStackTrace();
            return false;
         }
      }

      boolean isHashed() {
         return this.hashed;
      }

      void hash() {
         if (this.hashed)
            return;
         if (this.salt == null) {
            Random random = new Random() {
               private byte[] tmp = new byte[16];

               private SecureRandom random = null;

               public void fill(byte[] foo, int start, int len) {
                  if (len > this.tmp.length)
                     this.tmp = new byte[len];
                  this.random.nextBytes(this.tmp);
                  System.arraycopy(this.tmp, 0, foo, start, len);
               }
            };
            synchronized (random) {
               this.salt = new byte[KnownHosts.this.hmacsha1.getBlockSize()];
               random.fill(this.salt, 0, this.salt.length);
            }
         }
         try {
            synchronized (KnownHosts.this.hmacsha1) {
               KnownHosts.this.hmacsha1.init(this.salt);
               byte[] foo = Util.str2byte(this.host);
               KnownHosts.this.hmacsha1.update(foo, 0, foo.length);
               this.hash = new byte[KnownHosts.this.hmacsha1.getBlockSize()];
               KnownHosts.this.hmacsha1.doFinal(this.hash, 0);
            }
         } catch (Exception e) {
            e.printStackTrace();
            this.salt = null;
            this.hash = null;
            return;
         }
         this.host = "|1|" + Util.byte2str(Util.toBase64(this.salt, 0, this.salt.length, true)) + "|" +
                 Util.byte2str(Util.toBase64(this.hash, 0, this.hash.length, true));
         this.hashed = true;
      }
   }
}
