package com.mesosphere.sdk.offer.evaluate.security;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class SecretNameGeneratorTest {

    private SecretNameGenerator DEFAULT_GENERATOR;

    private SecretNameGenerator createGenerator(String serviceName, String podName, String taskName, String transportEncryptionName) {
        return new SecretNameGenerator(serviceName, podName, taskName, transportEncryptionName);
    }

    @Before
    public void init() {
        DEFAULT_GENERATOR = createGenerator("service", "pod","task", "exposed");
    }

    @Test
    public void getCertificatePath() throws Exception {
        Assert.assertEquals(DEFAULT_GENERATOR.getCertificatePath(), "service/pod/task/exposed/certificate");
    }

    @Test
    public void getPrivateKeyPath() throws Exception {
        Assert.assertEquals(DEFAULT_GENERATOR.getPrivateKeyPath(), "service/pod/task/exposed/private-key");
    }

    @Test
    public void getRootCACertPath() throws Exception {
        Assert.assertEquals(DEFAULT_GENERATOR.getRootCACertPath(), "service/pod/task/exposed/root-ca-certificate");
    }

    @Test
    public void getKeyStorePath() throws Exception {
        Assert.assertEquals(DEFAULT_GENERATOR.getKeyStorePath(), "service/pod/task/exposed/keystore");
    }

    @Test
    public void getTrustStorePath() throws Exception {
        Assert.assertEquals(DEFAULT_GENERATOR.getTrustStorePath(), "service/pod/task/exposed/truststore");
    }

    @Test
    public void getCertificateMountPath() throws Exception {
        Assert.assertEquals(DEFAULT_GENERATOR.getCertificateMountPath(), "exposed.crt");
    }

    @Test
    public void getPrivateKeyMountPath() throws Exception {
        Assert.assertEquals(DEFAULT_GENERATOR.getPrivateKeyMountPath(), "exposed.key");
    }

    @Test
    public void getRootCACertMountPath() throws Exception {
        Assert.assertEquals(DEFAULT_GENERATOR.getRootCACertMountPath(), "exposed.ca");
    }

    @Test
    public void getKeyStoreMountPath() throws Exception {
        Assert.assertEquals(DEFAULT_GENERATOR.getKeyStoreMountPath(), "exposed.keystore.base64");
    }

    @Test
    public void getTrustStoreMountPath() throws Exception {
        Assert.assertEquals(DEFAULT_GENERATOR.getTrustStoreMountPath(), "exposed.truststore.base64");
    }

}