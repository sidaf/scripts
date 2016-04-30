# java
alternatives --install /usr/bin/java java /usr/java/latest/jre/bin/java 20000 \
--slave /usr/bin/keytool keytool /usr/java/latest/bin/keytool \
--slave /usr/bin/orbd orbd /usr/java/latest/bin/orbd \
--slave /usr/bin/pack200 pack200 /usr/java/latest/bin/pack200 \
--slave /usr/bin/rmid rmid /usr/java/latest/bin/rmid \
--slave /usr/bin/rmiregistry rmiregistry /usr/java/latest/bin/rmiregistry \
--slave /usr/bin/servertool servertool /usr/java/latest/bin/servertool \
--slave /usr/bin/tnameserv tnameserv /usr/java/latest/bin/tnameserv \
--slave /usr/bin/unpack200 unpack200 /usr/java/latest/bin/unpack200 \
--slave /usr/lib/jvm/jre jre /usr/java/latest/jre


# javac
alternatives --install /usr/bin/javac javac /usr/java/latest/bin/javac 20000 \
--slave /usr/bin/appletviewer appletviewer /usr/java/latest/bin/appletviewer \
--slave /usr/bin/apt apt /usr/java/latest/bin/apt \
--slave /usr/bin/extcheck extcheck /usr/java/latest/bin/extcheck \
--slave /usr/bin/idlj idlj /usr/java/latest/bin/idlj \
--slave /usr/bin/jar jar /usr/java/latest/bin/jar \
--slave /usr/bin/jarsigner jarsigner /usr/java/latest/bin/jarsigner \
--slave /usr/bin/javadoc javadoc /usr/java/latest/bin/javadoc \
--slave /usr/bin/javah javah /usr/java/latest/bin/javah \
--slave /usr/bin/javap javap /usr/java/latest/bin/javap \
--slave /usr/bin/jcmd jcmd /usr/java/latest/bin/jcmd \
--slave /usr/bin/jconsole jconsole /usr/java/latest/bin/jconsole \
--slave /usr/bin/jdb jdb /usr/java/latest/bin/jdb \
--slave /usr/bin/jhat jhat /usr/java/latest/bin/jhat \
--slave /usr/bin/jinfo jinfo /usr/java/latest/bin/jinfo \
--slave /usr/bin/jmap jmap /usr/java/latest/bin/jmap \
--slave /usr/bin/jps jps /usr/java/latest/bin/jps \
--slave /usr/bin/jrunscript jrunscript /usr/java/latest/bin/jrunscript \
--slave /usr/bin/jdb jdb /usr/java/latest/bin/jdb \
--slave /usr/bin/jsadebugd jsadebugd /usr/java/latest/bin/jsadebugd \
--slave /usr/bin/jstack jstack /usr/java/latest/bin/jstack \
--slave /usr/bin/jstat jstat /usr/java/latest/bin/jstat \
--slave /usr/bin/jstatd jstatd /usr/java/latest/bin/jstatd \
--slave /usr/bin/native2ascii native2ascii /usr/java/latest/bin/native2ascii \
--slave /usr/bin/policytool policytool /usr/java/latest/bin/policytool \
--slave /usr/bin/rmic rmic /usr/java/latest/bin/rmic \
--slave /usr/bin/schemagen schemagen /usr/java/latest/bin/schemagen \
--slave /usr/bin/serialver serialver /usr/java/latest/bin/serialver \
--slave /usr/bin/wsgen wsgen /usr/java/latest/bin/wsgen \
--slave /usr/bin/wsimport wsimport /usr/java/latest/bin/wsimport \
--slave /usr/bin/xjc xjc /usr/java/latest/bin/xjc

# applet
alternatives --install /usr/lib64/mozilla/plugins/libjavaplugin.so libjavaplugin.so.x86_64 /usr/java/latest/jre/lib/amd64/libnpjp2.so 20000 \
--slave /usr/bin/javaws javaws /usr/java/latest/bin/javaws

