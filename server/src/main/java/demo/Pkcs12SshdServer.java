package demo;

import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.command.AbstractCommandSupport;
import org.apache.sshd.server.command.Command;
import org.apache.sshd.server.command.CommandFactory;
import org.apache.sshd.server.channel.ChannelSession;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.kex.BuiltinDHFactories;
import org.apache.sshd.common.kex.KeyExchange;
import org.apache.sshd.common.kex.KeyExchangeFactory;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;

import java.io.FileInputStream;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

public class Pkcs12SshdServer {
    public static void main(String[] args) throws Exception {
        SecurityUtils.setFipsMode();
        Security.addProvider(new BouncyCastleFipsProvider());
        System.setProperty("org.bouncycastle.fips.approved_only", "true");

        int port = 2222;
        KeyStore serverStore = KeyStore.getInstance("PKCS12");
        serverStore.load(new FileInputStream("../server-ec521.p12"), "changeit".toCharArray());
        String serverAlias = serverStore.aliases().nextElement();
        var serverKey = serverStore.getKey(serverAlias, "changeit".toCharArray());
        var serverCert = serverStore.getCertificate(serverAlias);

        KeyStore clientStore = KeyStore.getInstance("PKCS12");
        clientStore.load(new FileInputStream("../client-ec521.p12"), "changeit".toCharArray());
        String clientAlias = clientStore.aliases().nextElement();
        Certificate clientCert = clientStore.getCertificate(clientAlias);
        PublicKey allowedKey = clientCert.getPublicKey();

        SshServer sshd = SshServer.setUpDefaultServer();
        sshd.setPort(port);
        sshd.setKeyPairProvider(session -> Collections
                .singletonList(new KeyPair(serverCert.getPublicKey(), (java.security.PrivateKey) serverKey)));

        sshd.setPublickeyAuthenticator((username, incomingKey, session) -> {
            System.out.println("Login attempt by " + username);
            System.out.println("Incoming key: " + Base64.getEncoder().encodeToString(incomingKey.getEncoded()));
            System.out.println("🔑 Client key: " + incomingKey.getAlgorithm() + " " + incomingKey.getFormat());
            return allowedKey.equals(incomingKey);
        });

        sshd.setCommandFactory(new CommandFactory() {
            @Override
            public Command createCommand(ChannelSession channel, String command) {
                return new AbstractCommandSupport(command, null) {
                    @Override
                    public void run() {
                        try {
                            getOutputStream().write(("Hello from EC521 server, you ran: " + command + "\n").getBytes());
                            getOutputStream().flush();
                        } catch (Exception e) {
                            e.printStackTrace();
                        } finally {
                            onExit(0);
                        }
                    }
                };
            }
        });

        sshd.start();
        System.out.println("Server started on port " + port);

        while (true) {
        }
    }
}
