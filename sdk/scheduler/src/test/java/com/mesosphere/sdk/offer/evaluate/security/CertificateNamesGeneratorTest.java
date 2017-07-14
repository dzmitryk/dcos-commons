package com.mesosphere.sdk.offer.evaluate.security;

import com.mesosphere.sdk.offer.Constants;
import com.mesosphere.sdk.testutils.TestConstants;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.junit.Assert;
import org.junit.Test;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class CertificateNamesGeneratorTest {

    @Test
    public void getSubject() throws Exception {
        CertificateNamesGenerator certificateNamesGenerator = new CertificateNamesGenerator(
                TestConstants.SERVICE_NAME, TestConstants.TASK_NAME);

        X500Name subject = certificateNamesGenerator.getSubject();

        RDN[] cnRDNs = subject.getRDNs(BCStyle.CN);
        Assert.assertEquals(cnRDNs.length, 1);
        Assert.assertEquals(cnRDNs[0].getFirst().getValue().toString(), TestConstants.SERVICE_NAME);
    }

    @Test
    public void getSANs() throws Exception {
        CertificateNamesGenerator certificateNamesGenerator = new CertificateNamesGenerator(
                TestConstants.SERVICE_NAME, TestConstants.TASK_NAME);

        GeneralNames sans = certificateNamesGenerator.getSANs();
        Assert.assertEquals(sans.getNames().length, 3);

        List<String> names = Arrays.stream(sans.getNames())
                .map(name -> name.getName().toString())
                .collect(Collectors.toList());

        String dnsNameWithTaskName = taskDnsName(
            TestConstants.TASK_NAME,
            TestConstants.SERVICE_NAME);

        String wildcardDnsName =  taskDnsName("*", TestConstants.SERVICE_NAME);

        String wildcardVipName = taskVipName("*", TestConstants.SERVICE_NAME);

        Assert.assertTrue(names.contains(dnsNameWithTaskName));
        Assert.assertTrue(names.contains(wildcardDnsName));
        Assert.assertTrue(names.contains(wildcardVipName));
    }

    @Test
    public void testSlashesInServiceName() throws Exception {
        String serviceNameWithSlashes = "service/name/with/slashes";
        String serviceNameWithoutSlashes = "servicenamewithslashes";

        CertificateNamesGenerator certificateNamesGenerator = new CertificateNamesGenerator(
                serviceNameWithSlashes, TestConstants.TASK_NAME);

        String cnName = certificateNamesGenerator
                .getSubject()
                .getRDNs(BCStyle.CN)[0]
                .getFirst()
                .getValue()
                .toString();
        Assert.assertEquals(cnName, serviceNameWithoutSlashes);

        List<String> names = Arrays.stream(certificateNamesGenerator.getSANs().getNames())
                .map(name -> name.getName().toString())
                .collect(Collectors.toList());

        String dnsNameWithTaskName = taskDnsName(
                TestConstants.TASK_NAME,
                serviceNameWithoutSlashes);

        String wildcardDnsName =  taskDnsName("*", serviceNameWithoutSlashes);

        String wildcardVipName = taskVipName("*", serviceNameWithoutSlashes);

        Assert.assertTrue(names.contains(dnsNameWithTaskName));
        Assert.assertTrue(names.contains(wildcardDnsName));
        Assert.assertTrue(names.contains(wildcardVipName));
    }

    private String taskDnsName(String taskName, String serviceName) {
         return String.format(
            "%s.%s.%s",
            taskName,
            serviceName,
            Constants.DNS_TLD);
    }

    private String taskVipName(String taskName, String serviceName) {
        return String.format(
            "%s.%s.%s",
            taskName,
            serviceName,
            Constants.DNS_TLD);
    }

}