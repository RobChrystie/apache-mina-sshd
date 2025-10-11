package demo;

import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.channel.ChannelSession;
import org.apache.sshd.server.command.AbstractCommandSupport;
import org.apache.sshd.server.command.Command;
import org.apache.sshd.server.command.CommandFactory;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.math.ec.ECPoint;

import java.io.FileInputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.spec.*;
import java.util.*;

public class Pkcs12SshdServer {

    public static void main(String[] args) throws Exception {
        SecurityUtils.setFipsMode();
        Security.addProvider(new BouncyCastleFipsProvider());
        System.setProperty("org.bouncycastle.fips.approved_only", "true");

        int port = 2222;
        KeyStore serverStore = KeyStore.getInstance("PKCS12");
        serverStore.load(new FileInputStream(args[0]), "changeit".toCharArray());
        String serverAlias = serverStore.aliases().nextElement();
        var serverKey = serverStore.getKey(serverAlias, "changeit".toCharArray());
        var serverCert = serverStore.getCertificate(serverAlias);

        KeyStore clientStore = KeyStore.getInstance("PKCS12");
        clientStore.load(new FileInputStream(args[1]), "changeit".toCharArray());
        String clientAlias = clientStore.aliases().nextElement();
        Certificate clientCert = clientStore.getCertificate(clientAlias);
        PublicKey allowedKey = clientCert.getPublicKey();

        System.out.println("Allowed key: " + Base64.getEncoder().encodeToString(allowedKey.getEncoded()));
        System.out.println("🔑 Allowed client key: " + allowedKey.getAlgorithm() + " " + allowedKey.getFormat());

        SshServer sshd = SshServer.setUpDefaultServer();
        sshd.setPort(port);
        sshd.setKeyPairProvider(session -> Collections
                .singletonList(new KeyPair(serverCert.getPublicKey(), (java.security.PrivateKey) serverKey)));

        sshd.setPublickeyAuthenticator((username, incomingKey, session) -> {
            System.out.println("Login attempt by " + username);
            System.out.println("Incoming key: " + Base64.getEncoder().encodeToString(incomingKey.getEncoded()));
            System.out.println("🔑 Incoming client key: " + incomingKey.getAlgorithm() + " " + incomingKey.getFormat());

            try {
                PublicKey normalized = toPublicKey(convertExplicitSpkiToNamed(incomingKey.getEncoded()));
                System.out.println("Normalized key: " + Base64.getEncoder().encodeToString(normalized.getEncoded()));
                return Arrays.equals(normalized.getEncoded(), allowedKey.getEncoded());
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
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

    // Converts explicit EC params to named-curve SPKI if possible
    public static byte[] convertExplicitSpkiToNamed(byte[] spkiBytes) {
        try {
            SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(spkiBytes));
            ASN1Encodable params = spki.getAlgorithm().getParameters();
            if (params == null || params instanceof ASN1ObjectIdentifier) return spkiBytes;

            X9ECParameters explicit = X9ECParameters.getInstance(params);
            ASN1ObjectIdentifier oid = findNamedCurveOid(explicit);
            if (oid == null) {
                System.out.println("⚠️ No matching named curve found.");
                return spkiBytes;
            }

            AlgorithmIdentifier algId = new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, oid);
            return new SubjectPublicKeyInfo(algId, spki.getPublicKeyData().getBytes()).getEncoded();
        } catch (Exception e) {
            System.out.println("convertExplicitSpkiToNamed failed: " + e);
            return spkiBytes;
        }
    }

    // Converts SPKI bytes to Java PublicKey
    public static PublicKey toPublicKey(byte[] spkiBytes) throws Exception {
        X509EncodedKeySpec spec = new X509EncodedKeySpec(spkiBytes);
        KeyFactory kf;
        try {
            kf = KeyFactory.getInstance("EC", "BCFIPS");
        } catch (Exception e) {
            kf = KeyFactory.getInstance("EC");
        }
        return kf.generatePublic(spec);
    }

    // Find a named curve OID that matches the explicit parameters
    private static ASN1ObjectIdentifier findNamedCurveOid(X9ECParameters target) {
        Enumeration<?> names = ECNamedCurveTable.getNames();
        while (names.hasMoreElements()) {
            String name = (String) names.nextElement();
            X9ECParameters cand = ECNamedCurveTable.getByName(name);
            if (cand != null && x9Equals(cand, target)) return ECNamedCurveTable.getOID(name);
        }

        Enumeration<?> nistNames = NISTNamedCurves.getNames();
        while (nistNames.hasMoreElements()) {
            String name = (String) nistNames.nextElement();
            X9ECParameters cand = NISTNamedCurves.getByName(name);
            if (cand != null && x9Equals(cand, target)) return NISTNamedCurves.getOID(name);
        }

        return null;
    }

    // Compare EC curve parameters and base point
    private static boolean x9Equals(X9ECParameters a, X9ECParameters b) {
        if (!a.getN().equals(b.getN())) return false;
        if (!a.getH().equals(b.getH())) return false;
        if (!a.getCurve().getA().toBigInteger().equals(b.getCurve().getA().toBigInteger())) return false;
        if (!a.getCurve().getB().toBigInteger().equals(b.getCurve().getB().toBigInteger())) return false;
        return a.getG().normalize().equals(b.getG().normalize());
    }

    /**
     * Robust mathematical comparison of two EC public keys.
     * Ignores encoding differences (compressed/uncompressed, explicit/named parameters).
     */
    public static boolean areEcPublicKeysMathematicallyEqual(byte[] spki1, byte[] spki2) {
        try {
            SubjectPublicKeyInfo info1 = SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(spki1));
            SubjectPublicKeyInfo info2 = SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(spki2));

            X9ECParameters curve1 = getCurveParams(info1);
            X9ECParameters curve2 = getCurveParams(info2);

            if (!x9Equals(curve1, curve2)) return false;

            ECPoint Q1 = curve1.getCurve().decodePoint(info1.getPublicKeyData().getBytes()).normalize();
            ECPoint Q2 = curve2.getCurve().decodePoint(info2.getPublicKeyData().getBytes()).normalize();

            return Q1.getAffineXCoord().toBigInteger().equals(Q2.getAffineXCoord().toBigInteger())
                    && Q1.getAffineYCoord().toBigInteger().equals(Q2.getAffineYCoord().toBigInteger());

        } catch (Exception e) {
            return false;
        }
    }

    // Extract curve parameters from SPKI (named or explicit)
    private static X9ECParameters getCurveParams(SubjectPublicKeyInfo info) {
        ASN1Encodable params = info.getAlgorithm().getParameters();
        if (params instanceof ASN1ObjectIdentifier) {
            ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) params;
            X9ECParameters p = ECNamedCurveTable.getByOID(oid);
            if (p == null) p = NISTNamedCurves.getByOID(oid);
            return p;
        }
        return X9ECParameters.getInstance(params);
    }

}
