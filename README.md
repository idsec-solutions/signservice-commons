![Logo](https://idsec-solutions.github.io/signservice-integration-api/img/idsec.png)

# signservice-commons

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) 

Core components for the IDsec Signature Service.

---

The [Swedish eID Framework](https://docs.swedenconnect.se/technical-framework/) defines a model for Federated Central Signing Services. The **signservice-commons** repository contains a set of core, and commons, components for such a Signature Service.

The **signservice-commons** repository comprises of:

### Maven BOM

A Maven BOM to be used by those including the signservice-commons artifacts.

##### Maven

[![Maven Central](https://img.shields.io/maven-central/v/se.idsec.signservice.commons/signservice-bom.svg)](https://central.sonatype.com/artifact/se.idsec.signservice.commons/signservice-bom)

```
<dependencyManagement>
  <dependencies>
    ...
    <dependency>
      <groupId>se.idsec.signservice.commons</groupId>
      <artifactId>signservice-bom</artifactId>
      <version>${signservice-bom.version}</version>
      <type>pom</type>
      <scope>import</scope>
    </dependency>
    ...
  </dependencies>
</dependencyManagement>
```

### signservice-commons

A library containing utilities for JAXB and XML processing, certificate utilities and interfaces for signing and signature validation. 

##### Maven

[![Maven Central](https://img.shields.io/maven-central/v/se.idsec.signservice.commons/signservice-commons.svg)](https://central.sonatype.com/artifact/se.idsec.signservice.commons/signservice-commons)


```
<dependency>
  <groupId>se.idsec.signservice.commons</groupId>
  <artifactId>signservice-commons</artifactId>
  <version>${signservice-commons.version}</version>
</dependency>
```

##### API documentation

Java API documentation for [signservice-commons](https://idsec-solutions.github.io/signservice-commons/javadoc/signservice-commons).

### signservice-xml-commons

Classes for XML signing and validation of XML signatures.

##### Maven

[![Maven Central](https://img.shields.io/maven-central/v/se.idsec.signservice.commons/signservice-xml-commons.svg)](https://central.sonatype.com/artifact/se.idsec.signservice.commons/signservice-xml-commons)

```
<dependency>
  <groupId>se.idsec.signservice.commons</groupId>
  <artifactId>signservice-xml-commons</artifactId>
  <version>${signservice-xml-commons.version}</version>
</dependency>
```

##### API documentation

Java API documentation for [signservice-xml-commons](https://idsec-solutions.github.io/signservice-commons/javadoc/xml-commons).

### signservice-pdf-commons

Classes for PDF signing and validation of PDF signatures.

##### Maven

[![Maven Central](https://img.shields.io/maven-central/v/se.idsec.signservice.commons/signservice-pdf-commons.svg)](https://central.sonatype.com/artifact/se.idsec.signservice.commons/signservice-pdf-commons)

```
<dependency>
  <groupId>se.idsec.signservice.commons</groupId>
  <artifactId>signservice-pdf-commons</artifactId>
  <version>${signservice-pdf-commons.version}</version>
</dependency>
```

##### API documentation

Java API documentation for [signservice-pdf-commons](https://idsec-solutions.github.io/signservice-commons/javadoc/pdf-commons).

---

Copyright &copy; 2019-2025, [IDsec Solutions AB](http://www.idsec.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
