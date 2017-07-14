package com.mesosphere.sdk.offer.evaluate.security;

import java.util.Arrays;
import java.util.Collection;

/**
 * Provides a way to generate paths for secrets storing a private key, a certificate and a keystore.
 */
public class SecretNameGenerator {

    private final String podName;
    private final String namespace;
    private final String taskName;
    private final String transportEncryptionName;

    public SecretNameGenerator(String namespace, String podName, String taskName, String transportEncryptionName) {
        this.namespace = namespace;
        this.podName = podName;
        this.taskName = taskName;
        this.transportEncryptionName = transportEncryptionName;
    }

    public String getTaskSecretsNamespace() {
        return String.format("%s/%s/%s/%s", namespace, podName, taskName, transportEncryptionName);
    }

    public Collection<String> getAllSecretPaths() {
        return Arrays.asList(
                getCertificatePath(),
                getPrivateKeyPath(),
                getRootCACertPath(),
                getKeyStorePath(),
                getTrustStorePath()
        );
    }

    public String getCertificatePath() {
        return getSecretPath("certificate");
    }

    public String getPrivateKeyPath() {
        return getSecretPath("private-key");
    }

    public String getRootCACertPath() {
        return getSecretPath("root-ca-certificate");
    }

    public String getKeyStorePath() {
        return getSecretPath("keystore");
    }

    public String getTrustStorePath() {
        return getSecretPath("truststore");
    }

    public String getCertificateMountPath() {
        return getMountPath("crt");
    }

    public String getPrivateKeyMountPath() {
        return getMountPath("key");
    }

    public String getRootCACertMountPath() {
        return getMountPath("ca");
    }

    public String getKeyStoreMountPath() {
        return withBase64Suffix(getMountPath("keystore"));
    }

    public String getTrustStoreMountPath() {
        return withBase64Suffix(getMountPath("truststore"));
    }

    private String getSecretPath(String name) {
        return String.format("%s/%s", getTaskSecretsNamespace(), name);
    }

    private String getMountPath(String suffix) {
        return String.format("%s.%s", transportEncryptionName, suffix);
    }

    // This should get removed once secrets store will support binary data
    // @see DCOS-16005
    private String withBase64Suffix(String path) {
        return path + ".base64";
    }
}
