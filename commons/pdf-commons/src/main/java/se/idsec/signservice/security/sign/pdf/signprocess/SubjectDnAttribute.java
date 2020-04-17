/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package se.idsec.signservice.security.sign.pdf.signprocess;

/**
 *
 * @author stefan
 */
public enum SubjectDnAttribute {
    cn("2.5.4.3"),
    givenName("2.5.4.42"),
    surname("2.5.4.4"),
    personnummer("1.2.752.29.4.13"),
    country("2.5.4.6"),
    locality("2.5.4.7"),
    serialNumber("2.5.4.5"),
    orgnaizationName("2.5.4.10"),
    orgnaizationalUnitName("2.5.4.11"),
    organizationIdentifier("2.5.4.97"),
    pseudonym("2.5.4.65"),
    dnQualifier("2.5.4.46"),
    title("2.5.4.12"),
    unknown("");
    
    private final String oid;

    private SubjectDnAttribute(String oid) {
        this.oid = oid;
    }

    public String getOid() {
        return oid;
    }
    
    public static SubjectDnAttribute getSubjectDnFromOid (String oid){
        for (SubjectDnAttribute subjDn:values()){
            if (oid.equalsIgnoreCase(subjDn.getOid())){
                return subjDn;
            }
        }
        return unknown;
    }
    
}
