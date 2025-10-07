package demo;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.client.channel.ChannelExec;
import org.apache.sshd.client.channel.ClientChannelEvent;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.Security;
import java.util.EnumSet;
import java.util.concurrent.TimeUnit;

public class Pkcs12SshdClient {
    public static void main(String[] args) throws Exception {
        SecurityUtils.setFipsMode();
        Security.addProvider(new BouncyCastleFipsProvider());
        System.setProperty("org.bouncycastle.fips.approved_only", "true");

        String host = "localhost";
        int port = 2222;
        String username = "test";
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(new FileInputStream("../client-ec521.p12"), "changeit".toCharArray());
        String alias = ks.aliases().nextElement();
        var key = ks.getKey(alias, "changeit".toCharArray());
        var cert = ks.getCertificate(alias);
        var kp = new java.security.KeyPair(cert.getPublicKey(), (java.security.PrivateKey) key);

        try (SshClient client = SshClient.setUpDefaultClient()) {
            client.start();

            try (ClientSession session = client.connect(username, host, port).verify(7L, TimeUnit.SECONDS)
                    .getSession()) {
                session.addPublicKeyIdentity(kp);
                session.auth().verify(5L, TimeUnit.SECONDS);

                System.out.println("✅ Authenticated!");

                try (ByteArrayOutputStream response = new ByteArrayOutputStream();
                        ChannelExec channel = session.createExecChannel("echo 'Hello from EC521 client'")) {
                    channel.setOut(response);
                    channel.open().verify(5L, TimeUnit.SECONDS);
                    channel.waitFor(EnumSet.of(ClientChannelEvent.CLOSED), 0);
                    System.out.println("Server response: " + response.toString());
                }
            }
        }
    }
}
