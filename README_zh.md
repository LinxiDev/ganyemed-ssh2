# Ganymed SSH-2
Ganymed SSH-2 for Java - build 264

[English](README.md), [中文](README_zh.md)

来源:https://github.com/balaiitm/ganymed264.git
问题描述：解决方案使用高版本的OpenSSH时，Ganymed SSH-2出现以下错误
```angular2html
java.io.IOException: Key exchange was not finished, connection is closed.
at ch.ethz.ssh2.transport.KexManager.getOrWaitForConnectionInfo(KexManager.java:75)
at ch.ethz.ssh2.transport.TransportManager.getConnectionInfo(TransportManager.java:169)
at ch.ethz.ssh2.Connection.connect(Connection.java:759)
at ch.ethz.ssh2.Connection.connect(Connection.java:628)
at com.esb.common.utils.GetServerResourcesUtil.login(GetServerResourcesUtil.java:16)
at com.esb.common.utils.GetServerResourcesUtil.remoteExec(GetServerResourcesUtil.java:23)
at Main.main(Main.java:36)
Caused by: java.io.IOException: Cannot negotiate, proposals do not match.
at ch.ethz.ssh2.transport.ClientKexManager.handleMessage(ClientKexManager.java:123)
at ch.ethz.ssh2.transport.TransportManager.receiveLoop(TransportManager.java:572)
at ch.ethz.ssh2.transport.TransportManager$1.run(TransportManager.java:261)
at java.lang.Thread.run(Thread.java:750)
```