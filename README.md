![Logo](https://github.com/idsec-solutions/idsec-solutions.github.io/blob/master/img/idsec.png)

# signservice-commons

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Core components for the IDsec Signature Service.

---

The [Swedish eID Framework](https://docs.swedenconnect.se/technical-framework/) defines a model for Federated Central Signing Services. The **signservice-commons** repository contains a set of core, and commons, components for such a Signature Service.

The **signservice-commons** repository comprises of:

* A Maven BOM to be used by those including the signservice-commons artifacts.

* signservice-commons - A library containing utilities for JAXB and XML processing, certificate utilities and interfaces for signing and signature validation.

* signservice-xml-commons - Classes for XML signing and validation of XML signatures.

* signservice-pdf-commons - Classes for PDF signing and validation of PDF signatures. *Work is ongoing*

### API documentation

* Java API documentation for [signservice-commons](https://idsec-solutions.github.io/signservice-commons/javadoc/signservice-commons).
* Java API documentation for [signservice-xml-commons](https://idsec-solutions.github.io/signservice-commons/javadoc/xml-commons).

### Maven

All artifacts from the **signservice-commons** repository are published to Maven central.

```
<dependency>
  <groupId>se.idsec.signservice.commons</groupId>
  <artifactId>signservice-commons</artifactId>
  <version>${signservice-commons.version}</version>
</dependency>

<dependency>
  <groupId>se.idsec.signservice.commons</groupId>
  <artifactId>signservice-xml-commons</artifactId>
  <version>${signservice-xml-commons.version}</version>
</dependency>
```

---Copyright &copy; 2019-2020, [IDsec Solutions AB](http://www.idsec.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
