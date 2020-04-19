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
package se.idsec.signservice.security.sign.pdf.verify;

import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;

/**
 * @author stefan
 */
public enum EcCurve {

  P256(X9ObjectIdentifiers.prime256v1.getId(), 256),
  P192(X9ObjectIdentifiers.prime192v1.getId(), 192),
  P224(SECObjectIdentifiers.secp224r1.getId(), 224),
  P381(SECObjectIdentifiers.secp384r1.getId(), 384),
  P521(SECObjectIdentifiers.secp521r1.getId(), 521),
  BP192(TeleTrusTObjectIdentifiers.brainpoolP192r1.getId(), 192),
  BP224(TeleTrusTObjectIdentifiers.brainpoolP224r1.getId(), 224),
  BP256(TeleTrusTObjectIdentifiers.brainpoolP256r1.getId(), 256),
  BP320(TeleTrusTObjectIdentifiers.brainpoolP320r1.getId(), 320),
  BP384(TeleTrusTObjectIdentifiers.brainpoolP384r1.getId(), 384),
  BP521(TeleTrusTObjectIdentifiers.brainpoolP512r1.getId(), 521),
  unknown(null, 0);

  String oid;
  int keyLength;

  private EcCurve(String oid, int keyLength) {
    this.oid = oid;
    this.keyLength = keyLength;
  }

  public String getOid() {
    return oid;
  }

  public int getKeyLength() {
    return keyLength;
  }

  public static EcCurve getEcCurveFromOid(String oid) {
    for (EcCurve curve : values()) {
      if (curve.getOid().equalsIgnoreCase(oid)) {
        return curve;
      }
    }
    return unknown;
  }

}
