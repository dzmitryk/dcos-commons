package com.mesosphere.sdk.offer.evaluate.security;

import com.mesosphere.sdk.api.EndpointUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;

/**
 * A {@link CertificateNamesGenerator} creates relevant names for given service pod.
 */
public class CertificateNamesGenerator {

    private String serviceName;
    private String taskName;

    public CertificateNamesGenerator(String serviceName, String taskName) {
        this.serviceName = serviceName;
        this.taskName = taskName;
    }

    /**
     * Returns a Subject for service certificate.
     * @return
     */
    public X500Name getSubject() {
       // TODO(mh): Should we somehow improve certificate name here? Right now it reflects only service
       //           name. Should we somehow add pod name and requested certificate name?
       return new CertificateSubjectBuilder()
                .setCommonName(removeSlashes(serviceName))
                .build();
    }

    /**
     * Returns additional Subject Alternative Names for service certificates.
     * @return
     */
    public GeneralNames getSANs() {
        String autoIpWildcardName = EndpointUtils.toAutoIpHostname(serviceName, "*");
        String autoIpTaskName = EndpointUtils.toAutoIpHostname(serviceName, taskName);

        EndpointUtils.VipInfo vipInfo = new EndpointUtils.VipInfo("*", 0);
        String vipWildcardName = EndpointUtils.toVipHostname(serviceName, vipInfo);

        // TODO(mh): Include all VIP names from TaskSpec

        GeneralNames subAtlNames = new GeneralNames(
                new GeneralName[]{
                        new GeneralName(GeneralName.dNSName, autoIpTaskName),
                        new GeneralName(GeneralName.dNSName, autoIpWildcardName),
                        new GeneralName(GeneralName.dNSName, vipWildcardName),
                }
        );

        return subAtlNames;
    }

    /**
     * "/group1/group2/group3/group4/group5/kafka" => "group1group2group3group4group5kafka".
     */
    private static String removeSlashes(String name) {
        return name.replace("/", "");
    }

}
