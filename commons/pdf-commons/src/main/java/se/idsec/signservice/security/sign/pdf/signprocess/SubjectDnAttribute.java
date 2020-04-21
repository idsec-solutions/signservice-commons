/*
 * Copyright 2019-2020 IDsec Solutions AB
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package se.idsec.signservice.security.sign.pdf.signprocess;

/**
 * Enumeration of common certificate subject attributes
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
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
