// Copyright 2018 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

function register(form) {
    var name = form.name.value;
    var company = form.company.value;
    var country = form.country.value.toUpperCase().substring(0,2);

    var keys = forge.pki.rsa.generateKeyPair(1024);
    var csr = forge.pki.createCertificationRequest();

    csr.publicKey = keys.publicKey;
    csr.setSubject([{
      name: 'commonName',
      value: name
    }, {
      name: 'countryName',
      value: country
    }, {
      name: 'organizationName',
      value: company
    }]);

    csr.sign(keys.privateKey);

    var verified = csr.verify();

    var pem = forge.pki.certificationRequestToPem(csr);

    $.ajax('/register', {
        method: 'POST',
        data: {'csr': pem}
    }).done((response) => {
        if (response.error) {
            alert('Something went wrong: ' + response.error);
            return;
        }

        var cert = forge.pki.certificateFromPem(response.result);
        var p12Asn1 = forge.pkcs12.toPkcs12Asn1(keys.privateKey, cert, '');
        var p12Der = forge.asn1.toDer(p12Asn1).getBytes();
        var p12b64 = forge.util.encode64(p12Der);

        var a = document.getElementById('p12');
        a.setAttribute('href', 'data:application/x-pkcs12;base64,' + p12b64);

        $('#reg_success').show();

    });
}
