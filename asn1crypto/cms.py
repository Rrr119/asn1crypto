# coding: utf-8

"""
ASN.1 type classes for cryptographic message syntax (CMS). Structures are also
compatible with PKCS#7. Exports the following items:

 - AuthenticatedData()
 - AuthEnvelopedData()
 - CompressedData()
 - ContentInfo()
 - DigestedData()
 - EncryptedData()
 - EnvelopedData()
 - SignedAndEnvelopedData()
 - SignedData()

Other type classes are defined that help compose the types listed above.

Most CMS structures in the wild are formatted as ContentInfo encapsulating one of the other types.
"""

from __future__ import unicode_literals, division, absolute_import, print_function

import hashlib
import hmac
from datetime import datetime

try:
    import zlib
except (ImportError):
    zlib = None

from .algos import (
    _ForceNullParameters,
    DigestAlgorithm,
    EncryptionAlgorithm,
    EncryptionAlgorithmId,
    HmacAlgorithm,
    KdfAlgorithm,
    RSAESOAEPParams,
    SignedDigestAlgorithm,
)
from .core import (
    Any,
    BitString,
    Choice,
    Enumerated,
    GeneralizedTime,
    Integer,
    ObjectIdentifier,
    OctetBitString,
    OctetString,
    ParsableOctetString,
    Sequence,
    SequenceOf,
    SetOf,
    UTCTime,
    UTF8String,
    Void,
)
from .crl import CertificateList
from .keys import PublicKeyInfo
from .ocsp import OCSPResponse
from ._types import byte_cls, int_types
from .util import timezone
from .x509 import Attributes, Certificate, Extensions, GeneralName, GeneralNames, Name


# These structures are taken from
# ftp://ftp.rsasecurity.com/pub/pkcs/ascii/pkcs-6.asc


class CMSVerificationError(ValueError):
    """
    Raised when a CMS signature, certificate chain or timestamp can not be
    verified.
    """


class CMSTimestampVerificationResult(object):
    """
    The result of verifying an RFC 3161 timestamp token.
    """

    def __init__(self, gen_time, policy, serial_number, tsa, tst_info, signed_data,
                 signer_certificate, certificate_chain):
        self.gen_time = gen_time
        self.policy = policy
        self.serial_number = serial_number
        self.tsa = tsa
        self.tst_info = tst_info
        self.signed_data = signed_data
        self.signer_certificate = signer_certificate
        self.certificate_chain = certificate_chain


class CMSSignerVerificationResult(object):
    """
    The result of verifying a single CMS SignerInfo.
    """

    def __init__(self, signer_info, certificate, certificate_chain, timestamp, verification_time):
        self.signer_info = signer_info
        self.certificate = certificate
        self.certificate_chain = certificate_chain
        self.timestamp = timestamp
        self.verification_time = verification_time


class CMSSignedDataVerificationResult(object):
    """
    The result of verifying all SignerInfo structures in a SignedData object.
    """

    def __init__(self, signers):
        self.signers = signers

    @property
    def timestamp(self):
        """
        :return:
            The timestamp of the first signer that has a verified timestamp,
            or None
        """

        for signer in self.signers:
            if signer.timestamp is not None:
                return signer.timestamp
        return None


class ExtendedCertificateInfo(Sequence):
    _fields = [
        ('version', Integer),
        ('certificate', Certificate),
        ('attributes', Attributes),
    ]


class ExtendedCertificate(Sequence):
    _fields = [
        ('extended_certificate_info', ExtendedCertificateInfo),
        ('signature_algorithm', SignedDigestAlgorithm),
        ('signature', OctetBitString),
    ]


# These structures are taken from https://tools.ietf.org/html/rfc5652,
# https://tools.ietf.org/html/rfc5083, http://tools.ietf.org/html/rfc2315,
# https://tools.ietf.org/html/rfc5940, https://tools.ietf.org/html/rfc3274,
# https://tools.ietf.org/html/rfc3281


class CMSVersion(Integer):
    _map = {
        0: 'v0',
        1: 'v1',
        2: 'v2',
        3: 'v3',
        4: 'v4',
        5: 'v5',
    }


class CMSAttributeType(ObjectIdentifier):
    _map = {
        '1.2.840.113549.1.9.3': 'content_type',
        '1.2.840.113549.1.9.4': 'message_digest',
        '1.2.840.113549.1.9.5': 'signing_time',
        '1.2.840.113549.1.9.6': 'counter_signature',
        # https://datatracker.ietf.org/doc/html/rfc2633#section-2.5.2
        '1.2.840.113549.1.9.15': 'smime_capabilities',
        # https://tools.ietf.org/html/rfc2633#page-26
        '1.2.840.113549.1.9.16.2.11': 'encrypt_key_pref',
        # https://tools.ietf.org/html/rfc3161#page-20
        '1.2.840.113549.1.9.16.2.14': 'signature_time_stamp_token',
        # https://tools.ietf.org/html/rfc6211#page-5
        '1.2.840.113549.1.9.52': 'cms_algorithm_protection',
        # https://docs.microsoft.com/en-us/previous-versions/hh968145(v%3Dvs.85)
        '1.3.6.1.4.1.311.2.4.1': 'microsoft_nested_signature',
        # Some places refer to this as SPC_RFC3161_OBJID, others szOID_RFC3161_counterSign.
        # https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-crypt_algorithm_identifier
        # refers to szOID_RFC3161_counterSign as "1.2.840.113549.1.9.16.1.4",
        # but that OID is also called szOID_TIMESTAMP_TOKEN. Because of there being
        # no canonical source for this OID, we give it our own name
        '1.3.6.1.4.1.311.3.3.1': 'microsoft_time_stamp_token',
    }


class Time(Choice):
    _alternatives = [
        ('utc_time', UTCTime),
        ('generalized_time', GeneralizedTime),
    ]


class ContentType(ObjectIdentifier):
    _map = {
        '1.2.840.113549.1.7.1': 'data',
        '1.2.840.113549.1.7.2': 'signed_data',
        '1.2.840.113549.1.7.3': 'enveloped_data',
        '1.2.840.113549.1.7.4': 'signed_and_enveloped_data',
        '1.2.840.113549.1.7.5': 'digested_data',
        '1.2.840.113549.1.7.6': 'encrypted_data',
        '1.2.840.113549.1.9.16.1.2': 'authenticated_data',
        '1.2.840.113549.1.9.16.1.9': 'compressed_data',
        '1.2.840.113549.1.9.16.1.23': 'authenticated_enveloped_data',
    }


class CMSAlgorithmProtection(Sequence):
    _fields = [
        ('digest_algorithm', DigestAlgorithm),
        ('signature_algorithm', SignedDigestAlgorithm, {'implicit': 1, 'optional': True}),
        ('mac_algorithm', HmacAlgorithm, {'implicit': 2, 'optional': True}),
    ]


class SetOfContentType(SetOf):
    _child_spec = ContentType


class SetOfOctetString(SetOf):
    _child_spec = OctetString


class SetOfTime(SetOf):
    _child_spec = Time


class SetOfAny(SetOf):
    _child_spec = Any


class SetOfCMSAlgorithmProtection(SetOf):
    _child_spec = CMSAlgorithmProtection


class CMSAttribute(Sequence):
    _fields = [
        ('type', CMSAttributeType),
        ('values', None),
    ]

    _oid_specs = {}

    def _values_spec(self):
        return self._oid_specs.get(self['type'].native, SetOfAny)

    _spec_callbacks = {
        'values': _values_spec
    }


class CMSAttributes(SetOf):
    _child_spec = CMSAttribute


class IssuerSerial(Sequence):
    _fields = [
        ('issuer', GeneralNames),
        ('serial', Integer),
        ('issuer_uid', OctetBitString, {'optional': True}),
    ]


class AttCertVersion(Integer):
    _map = {
        0: 'v1',
        1: 'v2',
    }


class AttCertSubject(Choice):
    _alternatives = [
        ('base_certificate_id', IssuerSerial, {'explicit': 0}),
        ('subject_name', GeneralNames, {'explicit': 1}),
    ]


class AttCertValidityPeriod(Sequence):
    _fields = [
        ('not_before_time', GeneralizedTime),
        ('not_after_time', GeneralizedTime),
    ]


class AttributeCertificateInfoV1(Sequence):
    _fields = [
        ('version', AttCertVersion, {'default': 'v1'}),
        ('subject', AttCertSubject),
        ('issuer', GeneralNames),
        ('signature', SignedDigestAlgorithm),
        ('serial_number', Integer),
        ('att_cert_validity_period', AttCertValidityPeriod),
        ('attributes', Attributes),
        ('issuer_unique_id', OctetBitString, {'optional': True}),
        ('extensions', Extensions, {'optional': True}),
    ]


class AttributeCertificateV1(Sequence):
    _fields = [
        ('ac_info', AttributeCertificateInfoV1),
        ('signature_algorithm', SignedDigestAlgorithm),
        ('signature', OctetBitString),
    ]


class DigestedObjectType(Enumerated):
    _map = {
        0: 'public_key',
        1: 'public_key_cert',
        2: 'other_objy_types',
    }


class ObjectDigestInfo(Sequence):
    _fields = [
        ('digested_object_type', DigestedObjectType),
        ('other_object_type_id', ObjectIdentifier, {'optional': True}),
        ('digest_algorithm', DigestAlgorithm),
        ('object_digest', OctetBitString),
    ]


class Holder(Sequence):
    _fields = [
        ('base_certificate_id', IssuerSerial, {'implicit': 0, 'optional': True}),
        ('entity_name', GeneralNames, {'implicit': 1, 'optional': True}),
        ('object_digest_info', ObjectDigestInfo, {'implicit': 2, 'optional': True}),
    ]


class V2Form(Sequence):
    _fields = [
        ('issuer_name', GeneralNames, {'optional': True}),
        ('base_certificate_id', IssuerSerial, {'explicit': 0, 'optional': True}),
        ('object_digest_info', ObjectDigestInfo, {'explicit': 1, 'optional': True}),
    ]


class AttCertIssuer(Choice):
    _alternatives = [
        ('v1_form', GeneralNames),
        ('v2_form', V2Form, {'implicit': 0}),
    ]


class IetfAttrValue(Choice):
    _alternatives = [
        ('octets', OctetString),
        ('oid', ObjectIdentifier),
        ('string', UTF8String),
    ]


class IetfAttrValues(SequenceOf):
    _child_spec = IetfAttrValue


class IetfAttrSyntax(Sequence):
    _fields = [
        ('policy_authority', GeneralNames, {'implicit': 0, 'optional': True}),
        ('values', IetfAttrValues),
    ]


class SetOfIetfAttrSyntax(SetOf):
    _child_spec = IetfAttrSyntax


class SvceAuthInfo(Sequence):
    _fields = [
        ('service', GeneralName),
        ('ident', GeneralName),
        ('auth_info', OctetString, {'optional': True}),
    ]


class SetOfSvceAuthInfo(SetOf):
    _child_spec = SvceAuthInfo


class RoleSyntax(Sequence):
    _fields = [
        ('role_authority', GeneralNames, {'implicit': 0, 'optional': True}),
        ('role_name', GeneralName, {'explicit': 1}),
    ]


class SetOfRoleSyntax(SetOf):
    _child_spec = RoleSyntax


class ClassList(BitString):
    _map = {
        0: 'unmarked',
        1: 'unclassified',
        2: 'restricted',
        3: 'confidential',
        4: 'secret',
        5: 'top_secret',
    }


class SecurityCategory(Sequence):
    _fields = [
        ('type', ObjectIdentifier, {'implicit': 0}),
        ('value', Any, {'explicit': 1}),
    ]


class SetOfSecurityCategory(SetOf):
    _child_spec = SecurityCategory


class Clearance(Sequence):
    _fields = [
        ('policy_id', ObjectIdentifier),
        ('class_list', ClassList, {'default': set(['unclassified'])}),
        ('security_categories', SetOfSecurityCategory, {'optional': True}),
    ]


class SetOfClearance(SetOf):
    _child_spec = Clearance


class BigTime(Sequence):
    _fields = [
        ('major', Integer),
        ('fractional_seconds', Integer),
        ('sign', Integer, {'optional': True}),
    ]


class LeapData(Sequence):
    _fields = [
        ('leap_time', BigTime),
        ('action', Integer),
    ]


class SetOfLeapData(SetOf):
    _child_spec = LeapData


class TimingMetrics(Sequence):
    _fields = [
        ('ntp_time', BigTime),
        ('offset', BigTime),
        ('delay', BigTime),
        ('expiration', BigTime),
        ('leap_event', SetOfLeapData, {'optional': True}),
    ]


class SetOfTimingMetrics(SetOf):
    _child_spec = TimingMetrics


class TimingPolicy(Sequence):
    _fields = [
        ('policy_id', SequenceOf, {'spec': ObjectIdentifier}),
        ('max_offset', BigTime, {'explicit': 0, 'optional': True}),
        ('max_delay', BigTime, {'explicit': 1, 'optional': True}),
    ]


class SetOfTimingPolicy(SetOf):
    _child_spec = TimingPolicy


class AttCertAttributeType(ObjectIdentifier):
    _map = {
        '1.3.6.1.5.5.7.10.1': 'authentication_info',
        '1.3.6.1.5.5.7.10.2': 'access_identity',
        '1.3.6.1.5.5.7.10.3': 'charging_identity',
        '1.3.6.1.5.5.7.10.4': 'group',
        '2.5.4.72': 'role',
        '2.5.4.55': 'clearance',
        '1.3.6.1.4.1.601.10.4.1': 'timing_metrics',
        '1.3.6.1.4.1.601.10.4.2': 'timing_policy',
    }


class AttCertAttribute(Sequence):
    _fields = [
        ('type', AttCertAttributeType),
        ('values', None),
    ]

    _oid_specs = {
        'authentication_info': SetOfSvceAuthInfo,
        'access_identity': SetOfSvceAuthInfo,
        'charging_identity': SetOfIetfAttrSyntax,
        'group': SetOfIetfAttrSyntax,
        'role': SetOfRoleSyntax,
        'clearance': SetOfClearance,
        'timing_metrics': SetOfTimingMetrics,
        'timing_policy': SetOfTimingPolicy,
    }

    def _values_spec(self):
        return self._oid_specs.get(self['type'].native, SetOfAny)

    _spec_callbacks = {
        'values': _values_spec
    }


class AttCertAttributes(SequenceOf):
    _child_spec = AttCertAttribute


class AttributeCertificateInfoV2(Sequence):
    _fields = [
        ('version', AttCertVersion),
        ('holder', Holder),
        ('issuer', AttCertIssuer),
        ('signature', SignedDigestAlgorithm),
        ('serial_number', Integer),
        ('att_cert_validity_period', AttCertValidityPeriod),
        ('attributes', AttCertAttributes),
        ('issuer_unique_id', OctetBitString, {'optional': True}),
        ('extensions', Extensions, {'optional': True}),
    ]


class AttributeCertificateV2(Sequence):
    # Handle the situation where a V2 cert is encoded as V1
    _bad_tag = 1

    _fields = [
        ('ac_info', AttributeCertificateInfoV2),
        ('signature_algorithm', SignedDigestAlgorithm),
        ('signature', OctetBitString),
    ]


class OtherCertificateFormat(Sequence):
    _fields = [
        ('other_cert_format', ObjectIdentifier),
        ('other_cert', Any),
    ]


class CertificateChoices(Choice):
    _alternatives = [
        ('certificate', Certificate),
        ('extended_certificate', ExtendedCertificate, {'implicit': 0}),
        ('v1_attr_cert', AttributeCertificateV1, {'implicit': 1}),
        ('v2_attr_cert', AttributeCertificateV2, {'implicit': 2}),
        ('other', OtherCertificateFormat, {'implicit': 3}),
    ]

    def validate(self, class_, tag, contents):
        """
        Ensures that the class and tag specified exist as an alternative. This
        custom version fixes parsing broken encodings there a V2 attribute
        # certificate is encoded as a V1

        :param class_:
            The integer class_ from the encoded value header

        :param tag:
            The integer tag from the encoded value header

        :param contents:
            A byte string of the contents of the value - used when the object
            is explicitly tagged

        :raises:
            ValueError - when value is not a valid alternative
        """

        super(CertificateChoices, self).validate(class_, tag, contents)
        if self._choice == 2:
            if AttCertVersion.load(Sequence.load(contents)[0].dump()).native == 'v2':
                self._choice = 3


class CertificateSet(SetOf):
    _child_spec = CertificateChoices


class ContentInfo(Sequence):
    _fields = [
        ('content_type', ContentType),
        ('content', Any, {'explicit': 0, 'optional': True}),
    ]

    _oid_pair = ('content_type', 'content')
    _oid_specs = {}


class SetOfContentInfo(SetOf):
    _child_spec = ContentInfo


class EncapsulatedContentInfo(Sequence):
    _fields = [
        ('content_type', ContentType),
        ('content', ParsableOctetString, {'explicit': 0, 'optional': True}),
    ]

    _oid_pair = ('content_type', 'content')
    _oid_specs = {}


class IssuerAndSerialNumber(Sequence):
    _fields = [
        ('issuer', Name),
        ('serial_number', Integer),
    ]


class SignerIdentifier(Choice):
    _alternatives = [
        ('issuer_and_serial_number', IssuerAndSerialNumber),
        ('subject_key_identifier', OctetString, {'implicit': 0}),
    ]


class DigestAlgorithms(SetOf):
    _child_spec = DigestAlgorithm


class CertificateRevocationLists(SetOf):
    _child_spec = CertificateList


class SCVPReqRes(Sequence):
    _fields = [
        ('request', ContentInfo, {'explicit': 0, 'optional': True}),
        ('response', ContentInfo),
    ]


class OtherRevInfoFormatId(ObjectIdentifier):
    _map = {
        '1.3.6.1.5.5.7.16.2': 'ocsp_response',
        '1.3.6.1.5.5.7.16.4': 'scvp',
    }


class OtherRevocationInfoFormat(Sequence):
    _fields = [
        ('other_rev_info_format', OtherRevInfoFormatId),
        ('other_rev_info', Any),
    ]

    _oid_pair = ('other_rev_info_format', 'other_rev_info')
    _oid_specs = {
        'ocsp_response': OCSPResponse,
        'scvp': SCVPReqRes,
    }


class RevocationInfoChoice(Choice):
    _alternatives = [
        ('crl', CertificateList),
        ('other', OtherRevocationInfoFormat, {'implicit': 1}),
    ]


class RevocationInfoChoices(SetOf):
    _child_spec = RevocationInfoChoice


class SignerInfo(Sequence):
    _fields = [
        ('version', CMSVersion),
        ('sid', SignerIdentifier),
        ('digest_algorithm', DigestAlgorithm),
        ('signed_attrs', CMSAttributes, {'implicit': 0, 'optional': True}),
        ('signature_algorithm', SignedDigestAlgorithm),
        ('signature', OctetString),
        ('unsigned_attrs', CMSAttributes, {'implicit': 1, 'optional': True}),
    ]

    def find_certificate(self, certificates):
        """
        Finds the certificate identified by the SignerIdentifier.

        :param certificates:
            An iterable of Certificate, CertificateChoices, cryptography
            Certificate objects or DER/PEM byte strings

        :raises:
            CMSVerificationError - when no matching certificate is present

        :return:
            An asn1crypto.x509.Certificate object
        """

        return _find_signer_certificate(self, _load_certificates(certificates)).asn1

    def verify_timestamp(self, trust_store=None, extra_certs=None, timestamp_trust_store=None):
        """
        Verifies the RFC 3161 timestamp token in the unsigned attributes and
        that its message imprint covers this SignerInfo's signature.

        :param trust_store:
            None, or a certificate or iterable of certificates to use as trust
            anchors when verifying the timestamp signer's certificate chain

        :param extra_certs:
            None, or a certificate or iterable of additional certificates to
            use while building the timestamp signer's certificate chain

        :param timestamp_trust_store:
            None, or a certificate or iterable of certificates to use as trust
            anchors for the timestamp signer. When not None, this takes
            precedence over trust_store.

        :raises:
            CMSVerificationError - when the timestamp is missing or invalid

        :return:
            A CMSTimestampVerificationResult object, or None if the SignerInfo
            does not contain a timestamp
        """

        values = _attribute_values(self['unsigned_attrs'], 'signature_time_stamp_token')
        if not values:
            return None

        if len(values) != 1:
            raise CMSVerificationError('SignerInfo contains more than one timestamp token')

        anchors = timestamp_trust_store if timestamp_trust_store is not None else trust_store
        return _verify_timestamp_token(self, values[0], anchors, extra_certs)

    def verify(self, certificates, content, trust_store=None, extra_certs=None, verification_time=None):
        """
        Verifies the content digest and signature of this SignerInfo.

        The certificate chain is verified when trust_store is not None.

        :param certificates:
            An iterable of candidate signer certificates

        :param content:
            The signed content as a byte string

        :param trust_store:
            None, or a certificate or iterable of trust anchors

        :param extra_certs:
            None, or additional certificates to use while building the chain

        :param verification_time:
            None, a datetime or a POSIX timestamp at which to validate the
            certificate chain

        :raises:
            CMSVerificationError - when verification fails

        :return:
            A CMSSignerVerificationResult object
        """

        candidates = _load_certificates(certificates)
        certificate = _find_signer_certificate(self, candidates)
        _verify_signer_crypto(self, certificate, content)
        effective_time = _normalize_verification_time(verification_time)
        chain = _verify_certificate_chain(certificate, candidates, trust_store, effective_time)
        return CMSSignerVerificationResult(self, certificate.asn1, chain, None, effective_time)

    verify_signature = verify


class SignerInfos(SetOf):
    _child_spec = SignerInfo


class SignedData(Sequence):
    _fields = [
        ('version', CMSVersion),
        ('digest_algorithms', DigestAlgorithms),
        ('encap_content_info', None),
        ('certificates', CertificateSet, {'implicit': 0, 'optional': True}),
        ('crls', RevocationInfoChoices, {'implicit': 1, 'optional': True}),
        ('signer_infos', SignerInfos),
    ]

    def _encap_content_info_spec(self):
        # If the encap_content_info is version v1, then this could be a PKCS#7
        # structure, or a CMS structure. CMS wraps the encoded value in an
        # Octet String tag.

        # If the version is greater than 1, it is definite CMS
        if self['version'].native != 'v1':
            return EncapsulatedContentInfo

        # Otherwise, the ContentInfo spec from PKCS#7 will be compatible with
        # CMS v1 (which only allows Data, an Octet String) and PKCS#7, which
        # allows Any
        return ContentInfo

    _spec_callbacks = {
        'encap_content_info': _encap_content_info_spec
    }

    def verify(self, content=None, trust_store=None, extra_certs=None, verification_time=None,
               require_timestamp=False, verify_timestamp=True, timestamp_trust_store=None,
               use_timestamp_for_validity=True, return_info=False, raise_errors=False,
               **kwargs):
        """
        Verifies all signatures, content digests and certificate chains in the
        SignedData structure.

        When a SignerInfo contains an RFC 3161 timestamp token, the timestamp
        is verified and, unless verification_time is explicitly provided, its
        generation time is used to validate the signer certificate chain.

        :param content:
            None to use the encapsulated content, or a byte string containing
            the detached content

        :param trust_store:
            None, or a certificate or iterable of certificates to use as trust
            anchors. When None, the signer and timestamp certificates are
            validated for time and signature but are not chained to an
            externally trusted anchor.

        :param extra_certs:
            None, or additional certificates to use while building chains

        :param verification_time:
            None, a datetime or a POSIX timestamp at which to validate
            certificate chains

        :param require_timestamp:
            A boolean indicating if every SignerInfo must contain a verified
            timestamp

        :param verify_timestamp:
            A boolean indicating if timestamp tokens should be verified

        :param timestamp_trust_store:
            None, or trust anchors for timestamp signers. When None, trust_store
            is used.

        :param use_timestamp_for_validity:
            A boolean indicating if the timestamp generation time should be used
            to validate the signer certificate chain

        :param return_info:
            A boolean indicating if a CMSSignedDataVerificationResult should be
            returned instead of True

        :param raise_errors:
            A boolean indicating if verification errors should be raised

        :raises:
            CMSVerificationError - when verification fails and return_info or
            raise_errors is True

        :return:
            A boolean, or a CMSSignedDataVerificationResult object
        """

        content = _compat_kwarg(content, kwargs, ('data',))
        trust_store = _compat_kwarg(
            trust_store,
            kwargs,
            ('trusted_certs', 'trusted_certificates', 'trust_roots', 'trust_anchors', 'ca_certs', 'truststore')
        )
        extra_certs = _compat_kwarg(extra_certs, kwargs, ('intermediates',))
        if kwargs:
            raise TypeError('Unexpected keyword argument: %s' % sorted(kwargs.keys())[0])

        try:
            result = _verify_signed_data(
                self,
                content,
                trust_store,
                extra_certs,
                verification_time,
                require_timestamp,
                verify_timestamp,
                timestamp_trust_store,
                use_timestamp_for_validity
            )
        except CMSVerificationError:
            if return_info or raise_errors:
                raise
            return False
        except (AttributeError, IndexError, KeyError, TypeError, ValueError) as e:
            error = CMSVerificationError('Unable to verify SignedData: %s' % e)
            if return_info or raise_errors:
                raise error
            return False

        if return_info:
            return result
        return True

    verify_signature = verify

    def verify_timestamp(self, signer=0, trust_store=None, extra_certs=None, timestamp_trust_store=None):
        """
        Verifies the timestamp token of a SignerInfo.

        :param signer:
            An integer index into signer_infos, or a SignerInfo object

        :param trust_store:
            None, or trust anchors for the timestamp signer

        :param extra_certs:
            None, or additional certificates for chain building

        :param timestamp_trust_store:
            None, or timestamp-specific trust anchors

        :raises:
            CMSVerificationError - when the timestamp is missing or invalid

        :return:
            A CMSTimestampVerificationResult object
        """

        if isinstance(signer, int_types):
            signer = self['signer_infos'][signer]
        result = signer.verify_timestamp(trust_store, extra_certs, timestamp_trust_store)
        if result is None:
            raise CMSVerificationError('SignerInfo does not contain a timestamp token')
        return result

    def certificate_chain(self, signer=0, trust_store=None, extra_certs=None, verification_time=None):
        """
        Builds and verifies the certificate chain for a SignerInfo.

        :param signer:
            An integer index into signer_infos, or a SignerInfo object

        :param trust_store:
            A certificate or iterable of trust anchors

        :param extra_certs:
            None, or additional certificates for chain building

        :param verification_time:
            None, a datetime or a POSIX timestamp for validity checking

        :raises:
            CMSVerificationError - when the chain can not be verified

        :return:
            A list of asn1crypto.x509.Certificate objects, starting with the
            signer certificate
        """

        if isinstance(signer, int_types):
            signer = self['signer_infos'][signer]
        candidates = _get_signed_data_certificates(self, extra_certs)
        certificate = _find_signer_certificate(signer, candidates)
        effective_time = _normalize_verification_time(verification_time)
        return _verify_certificate_chain(certificate, candidates, trust_store, effective_time)

    def verify_certificate_chain(self, signer=0, trust_store=None, extra_certs=None, verification_time=None):
        """
        Verifies the certificate chain for a SignerInfo and returns a boolean.
        """

        try:
            self.certificate_chain(signer, trust_store, extra_certs, verification_time)
        except CMSVerificationError:
            return False
        return True

    verify_chain = verify_certificate_chain


class OriginatorInfo(Sequence):
    _fields = [
        ('certs', CertificateSet, {'implicit': 0, 'optional': True}),
        ('crls', RevocationInfoChoices, {'implicit': 1, 'optional': True}),
    ]


class RecipientIdentifier(Choice):
    _alternatives = [
        ('issuer_and_serial_number', IssuerAndSerialNumber),
        ('subject_key_identifier', OctetString, {'implicit': 0}),
    ]


class KeyEncryptionAlgorithmId(ObjectIdentifier):
    _map = {
        '1.2.840.113549.1.1.1': 'rsaes_pkcs1v15',
        '1.2.840.113549.1.1.7': 'rsaes_oaep',
        '2.16.840.1.101.3.4.1.5': 'aes128_wrap',
        '2.16.840.1.101.3.4.1.8': 'aes128_wrap_pad',
        '2.16.840.1.101.3.4.1.25': 'aes192_wrap',
        '2.16.840.1.101.3.4.1.28': 'aes192_wrap_pad',
        '2.16.840.1.101.3.4.1.45': 'aes256_wrap',
        '2.16.840.1.101.3.4.1.48': 'aes256_wrap_pad',
    }

    _reverse_map = {
        'rsa': '1.2.840.113549.1.1.1',
        'rsaes_pkcs1v15': '1.2.840.113549.1.1.1',
        'rsaes_oaep': '1.2.840.113549.1.1.7',
        'aes128_wrap': '2.16.840.1.101.3.4.1.5',
        'aes128_wrap_pad': '2.16.840.1.101.3.4.1.8',
        'aes192_wrap': '2.16.840.1.101.3.4.1.25',
        'aes192_wrap_pad': '2.16.840.1.101.3.4.1.28',
        'aes256_wrap': '2.16.840.1.101.3.4.1.45',
        'aes256_wrap_pad': '2.16.840.1.101.3.4.1.48',
    }


class KeyEncryptionAlgorithm(_ForceNullParameters, Sequence):
    _fields = [
        ('algorithm', KeyEncryptionAlgorithmId),
        ('parameters', Any, {'optional': True}),
    ]

    _oid_pair = ('algorithm', 'parameters')
    _oid_specs = {
        'rsaes_oaep': RSAESOAEPParams,
    }


class KeyTransRecipientInfo(Sequence):
    _fields = [
        ('version', CMSVersion),
        ('rid', RecipientIdentifier),
        ('key_encryption_algorithm', KeyEncryptionAlgorithm),
        ('encrypted_key', OctetString),
    ]


class OriginatorIdentifierOrKey(Choice):
    _alternatives = [
        ('issuer_and_serial_number', IssuerAndSerialNumber),
        ('subject_key_identifier', OctetString, {'implicit': 0}),
        ('originator_key', PublicKeyInfo, {'implicit': 1}),
    ]


class OtherKeyAttribute(Sequence):
    _fields = [
        ('key_attr_id', ObjectIdentifier),
        ('key_attr', Any),
    ]


class RecipientKeyIdentifier(Sequence):
    _fields = [
        ('subject_key_identifier', OctetString),
        ('date', GeneralizedTime, {'optional': True}),
        ('other', OtherKeyAttribute, {'optional': True}),
    ]

    def _setup(self):
        super(RecipientKeyIdentifier, self)._setup()
        # This creates a backwards compatible shim for an
        # incorrect format field name that was in old versions
        self._field_map['subjectKeyIdentifier'] = self._field_map['subject_key_identifier']


class KeyAgreementRecipientIdentifier(Choice):
    _alternatives = [
        ('issuer_and_serial_number', IssuerAndSerialNumber),
        ('r_key_id', RecipientKeyIdentifier, {'implicit': 0}),
    ]


class RecipientEncryptedKey(Sequence):
    _fields = [
        ('rid', KeyAgreementRecipientIdentifier),
        ('encrypted_key', OctetString),
    ]


class RecipientEncryptedKeys(SequenceOf):
    _child_spec = RecipientEncryptedKey


class KeyAgreeRecipientInfo(Sequence):
    _fields = [
        ('version', CMSVersion),
        ('originator', OriginatorIdentifierOrKey, {'explicit': 0}),
        ('ukm', OctetString, {'explicit': 1, 'optional': True}),
        ('key_encryption_algorithm', KeyEncryptionAlgorithm),
        ('recipient_encrypted_keys', RecipientEncryptedKeys),
    ]


class KEKIdentifier(Sequence):
    _fields = [
        ('key_identifier', OctetString),
        ('date', GeneralizedTime, {'optional': True}),
        ('other', OtherKeyAttribute, {'optional': True}),
    ]


class KEKRecipientInfo(Sequence):
    _fields = [
        ('version', CMSVersion),
        ('kekid', KEKIdentifier),
        ('key_encryption_algorithm', KeyEncryptionAlgorithm),
        ('encrypted_key', OctetString),
    ]


class PasswordRecipientInfo(Sequence):
    _fields = [
        ('version', CMSVersion),
        ('key_derivation_algorithm', KdfAlgorithm, {'implicit': 0, 'optional': True}),
        ('key_encryption_algorithm', KeyEncryptionAlgorithm),
        ('encrypted_key', OctetString),
    ]


class OtherRecipientInfo(Sequence):
    _fields = [
        ('ori_type', ObjectIdentifier),
        ('ori_value', Any),
    ]


class RecipientInfo(Choice):
    _alternatives = [
        ('ktri', KeyTransRecipientInfo),
        ('kari', KeyAgreeRecipientInfo, {'implicit': 1}),
        ('kekri', KEKRecipientInfo, {'implicit': 2}),
        ('pwri', PasswordRecipientInfo, {'implicit': 3}),
        ('ori', OtherRecipientInfo, {'implicit': 4}),
    ]


class RecipientInfos(SetOf):
    _child_spec = RecipientInfo


class EncryptedContentInfo(Sequence):
    _fields = [
        ('content_type', ContentType),
        ('content_encryption_algorithm', EncryptionAlgorithm),
        ('encrypted_content', OctetString, {'implicit': 0, 'optional': True}),
    ]


class EnvelopedData(Sequence):
    _fields = [
        ('version', CMSVersion),
        ('originator_info', OriginatorInfo, {'implicit': 0, 'optional': True}),
        ('recipient_infos', RecipientInfos),
        ('encrypted_content_info', EncryptedContentInfo),
        ('unprotected_attrs', CMSAttributes, {'implicit': 1, 'optional': True}),
    ]


class SignedAndEnvelopedData(Sequence):
    _fields = [
        ('version', CMSVersion),
        ('recipient_infos', RecipientInfos),
        ('digest_algorithms', DigestAlgorithms),
        ('encrypted_content_info', EncryptedContentInfo),
        ('certificates', CertificateSet, {'implicit': 0, 'optional': True}),
        ('crls', CertificateRevocationLists, {'implicit': 1, 'optional': True}),
        ('signer_infos', SignerInfos),
    ]


class DigestedData(Sequence):
    _fields = [
        ('version', CMSVersion),
        ('digest_algorithm', DigestAlgorithm),
        ('encap_content_info', None),
        ('digest', OctetString),
    ]

    def _encap_content_info_spec(self):
        # If the encap_content_info is version v1, then this could be a PKCS#7
        # structure, or a CMS structure. CMS wraps the encoded value in an
        # Octet String tag.

        # If the version is greater than 1, it is definite CMS
        if self['version'].native != 'v1':
            return EncapsulatedContentInfo

        # Otherwise, the ContentInfo spec from PKCS#7 will be compatible with
        # CMS v1 (which only allows Data, an Octet String) and PKCS#7, which
        # allows Any
        return ContentInfo

    _spec_callbacks = {
        'encap_content_info': _encap_content_info_spec
    }


class EncryptedData(Sequence):
    _fields = [
        ('version', CMSVersion),
        ('encrypted_content_info', EncryptedContentInfo),
        ('unprotected_attrs', CMSAttributes, {'implicit': 1, 'optional': True}),
    ]


class AuthenticatedData(Sequence):
    _fields = [
        ('version', CMSVersion),
        ('originator_info', OriginatorInfo, {'implicit': 0, 'optional': True}),
        ('recipient_infos', RecipientInfos),
        ('mac_algorithm', HmacAlgorithm),
        ('digest_algorithm', DigestAlgorithm, {'implicit': 1, 'optional': True}),
        # This does not require the _spec_callbacks approach of SignedData and
        # DigestedData since AuthenticatedData was not part of PKCS#7
        ('encap_content_info', EncapsulatedContentInfo),
        ('auth_attrs', CMSAttributes, {'implicit': 2, 'optional': True}),
        ('mac', OctetString),
        ('unauth_attrs', CMSAttributes, {'implicit': 3, 'optional': True}),
    ]


class AuthEnvelopedData(Sequence):
    _fields = [
        ('version', CMSVersion),
        ('originator_info', OriginatorInfo, {'implicit': 0, 'optional': True}),
        ('recipient_infos', RecipientInfos),
        ('auth_encrypted_content_info', EncryptedContentInfo),
        ('auth_attrs', CMSAttributes, {'implicit': 1, 'optional': True}),
        ('mac', OctetString),
        ('unauth_attrs', CMSAttributes, {'implicit': 2, 'optional': True}),
    ]


class CompressionAlgorithmId(ObjectIdentifier):
    _map = {
        '1.2.840.113549.1.9.16.3.8': 'zlib',
    }


class CompressionAlgorithm(Sequence):
    _fields = [
        ('algorithm', CompressionAlgorithmId),
        ('parameters', Any, {'optional': True}),
    ]


class CompressedData(Sequence):
    _fields = [
        ('version', CMSVersion),
        ('compression_algorithm', CompressionAlgorithm),
        ('encap_content_info', EncapsulatedContentInfo),
    ]

    _decompressed = None

    @property
    def decompressed(self):
        if self._decompressed is None:
            if zlib is None:
                raise SystemError('The zlib module is not available')
            self._decompressed = zlib.decompress(self['encap_content_info']['content'].native)
        return self._decompressed


class SMIMEEncryptionKeyPreference(Choice):
    _alternatives = [
        ('issuer_and_serial_number', IssuerAndSerialNumber, {'implicit': 0}),
        ('recipient_key_id', RecipientKeyIdentifier, {'implicit': 1}),
        ('subject_alt_key_identifier', PublicKeyInfo, {'implicit': 2}),
    ]

    def _setup(self):
        super(SMIMEEncryptionKeyPreference, self)._setup()
        # This creates backwards compatible shims for two
        # incorrect format alternative names that were in old versions
        self._name_map['recipientKeyId'] = self._name_map['recipient_key_id']
        self._name_map['subjectAltKeyIdentifier'] = self._name_map['subject_alt_key_identifier']


class SMIMEEncryptionKeyPreferences(SetOf):
    _child_spec = SMIMEEncryptionKeyPreference


class SMIMECapabilityIdentifier(Sequence):
    _fields = [
        ('capability_id', EncryptionAlgorithmId),
        ('parameters', Any, {'optional': True}),
    ]


class SMIMECapabilites(SequenceOf):
    _child_spec = SMIMECapabilityIdentifier


class SetOfSMIMECapabilites(SetOf):
    _child_spec = SMIMECapabilites


ContentInfo._oid_specs = {
    'data': OctetString,
    'signed_data': SignedData,
    'enveloped_data': EnvelopedData,
    'signed_and_enveloped_data': SignedAndEnvelopedData,
    'digested_data': DigestedData,
    'encrypted_data': EncryptedData,
    'authenticated_data': AuthenticatedData,
    'compressed_data': CompressedData,
    'authenticated_enveloped_data': AuthEnvelopedData,
}


EncapsulatedContentInfo._oid_specs = {
    'signed_data': SignedData,
    'enveloped_data': EnvelopedData,
    'signed_and_enveloped_data': SignedAndEnvelopedData,
    'digested_data': DigestedData,
    'encrypted_data': EncryptedData,
    'authenticated_data': AuthenticatedData,
    'compressed_data': CompressedData,
    'authenticated_enveloped_data': AuthEnvelopedData,
}


CMSAttribute._oid_specs = {
    'content_type': SetOfContentType,
    'message_digest': SetOfOctetString,
    'signing_time': SetOfTime,
    'counter_signature': SignerInfos,
    'signature_time_stamp_token': SetOfContentInfo,
    'cms_algorithm_protection': SetOfCMSAlgorithmProtection,
    'microsoft_nested_signature': SetOfContentInfo,
    'microsoft_time_stamp_token': SetOfContentInfo,
    'encrypt_key_pref': SMIMEEncryptionKeyPreferences,
    'smime_capabilities': SetOfSMIMECapabilites,
}


class _LoadedCertificate(object):

    def __init__(self, asn1, crypto):
        self.asn1 = asn1
        self.crypto = crypto
        self.der = asn1.dump()


def _is_void(value):
    return value is None or isinstance(value, Void)


def _compat_kwarg(value, kwargs, names):
    for name in names:
        if name in kwargs:
            alias_value = kwargs.pop(name)
            if value is None:
                value = alias_value
    return value


def _cryptography_x509():
    try:
        from cryptography import x509 as crypto_x509
    except (ImportError):
        raise CMSVerificationError(
            'The cryptography package is required to verify CMS signatures'
        )
    return crypto_x509


def _is_cryptography_certificate(value):
    crypto_x509 = _cryptography_x509()
    return isinstance(value, crypto_x509.Certificate)


def _load_certificate(value):
    if isinstance(value, _LoadedCertificate):
        return value

    if isinstance(value, CertificateChoices):
        if value.name != 'certificate':
            raise CMSVerificationError('CMS certificate choice does not contain an X.509 certificate')
        value = value.chosen

    crypto_x509 = _cryptography_x509()

    if isinstance(value, Certificate):
        asn1_certificate = value
        der = value.dump()
        crypto_certificate = crypto_x509.load_der_x509_certificate(der)
        return _LoadedCertificate(asn1_certificate, crypto_certificate)

    if isinstance(value, crypto_x509.Certificate):
        der = value.public_bytes(_cryptography_encoding())
        return _LoadedCertificate(Certificate.load(der), value)

    if isinstance(value, bytearray):
        value = bytes(value)

    if isinstance(value, byte_cls):
        try:
            if value.lstrip().startswith(b'-----BEGIN'):
                crypto_certificate = crypto_x509.load_pem_x509_certificate(value)
                der = crypto_certificate.public_bytes(_cryptography_encoding())
            else:
                der = value
                crypto_certificate = crypto_x509.load_der_x509_certificate(der)
            return _LoadedCertificate(Certificate.load(der), crypto_certificate)
        except (ValueError, TypeError) as e:
            raise CMSVerificationError('Unable to parse certificate: %s' % e)

    raise CMSVerificationError('Unsupported certificate value of type %s' % type(value).__name__)


def _cryptography_encoding():
    from cryptography.hazmat.primitives.serialization import Encoding
    return Encoding.DER


def _load_certificates(values):
    if values is None:
        return []

    single_types = (_LoadedCertificate, CertificateChoices, Certificate)
    is_single = isinstance(values, single_types) or isinstance(values, byte_cls)
    if not is_single:
        is_single = _is_cryptography_certificate(values)

    if is_single:
        values = [values]

    try:
        certificates = [_load_certificate(value) for value in values]
    except TypeError:
        raise CMSVerificationError('Certificates must be a certificate or an iterable of certificates')

    output = []
    seen = set()
    for certificate in certificates:
        if certificate.der in seen:
            continue
        seen.add(certificate.der)
        output.append(certificate)
    return output


def _certificate_choices_to_certificates(certificates):
    if _is_void(certificates):
        return []
    output = []
    for choice in certificates:
        if choice.name == 'certificate':
            output.append(_load_certificate(choice))
    return output


def _get_signed_data_certificates(signed_data, extra_certs=None):
    certificates = _certificate_choices_to_certificates(signed_data['certificates'])
    if extra_certs is not None:
        certificates.extend(_load_certificates(extra_certs))
    return _load_certificates(certificates)


def _find_signer_certificate(signer_info, certificates):
    sid = signer_info['sid']
    if sid.name == 'issuer_and_serial_number':
        issuer_serial = sid.chosen
        for certificate in certificates:
            asn1_certificate = certificate.asn1
            if asn1_certificate.issuer == issuer_serial['issuer'] and \
                    asn1_certificate.serial_number == issuer_serial['serial_number'].native:
                return certificate
        raise CMSVerificationError('Unable to locate the signer certificate by issuer and serial number')

    subject_key_identifier = sid.chosen.native
    for certificate in certificates:
        if certificate.asn1.key_identifier == subject_key_identifier:
            return certificate
    raise CMSVerificationError('Unable to locate the signer certificate by subject key identifier')


def _attribute_values(attributes, attribute_type):
    if _is_void(attributes):
        return []
    output = []
    for attribute in attributes:
        if attribute['type'].native == attribute_type:
            values = attribute['values']
            if not _is_void(values):
                output.extend(list(values))
    return output


def _constant_time_equals(left, right):
    if hasattr(hmac, 'compare_digest'):
        return hmac.compare_digest(left, right)
    if len(left) != len(right):
        return False
    result = 0
    for left_byte, right_byte in zip(bytearray(left), bytearray(right)):
        result |= left_byte ^ right_byte
    return result == 0


def _digest_bytes(hash_algo, data):
    hash_name = hash_algo.replace('-', '_').lower()
    try:
        return hashlib.new(hash_name, data).digest()
    except (ValueError, TypeError) as e:
        raise CMSVerificationError('Unsupported digest algorithm %s: %s' % (hash_algo, e))


def _signed_attributes_der(attributes):
    encoded = attributes.dump()
    tag = bytearray(encoded[:1])[0]
    if tag != 0x31:
        encoded = b'\x31' + encoded[1:]
    return encoded


def _content_bytes(content):
    if _is_void(content):
        raise CMSVerificationError('The signed content is not available')

    if isinstance(content, bytearray):
        return bytes(content)

    if isinstance(content, byte_cls):
        return content

    if hasattr(content, '__bytes__'):
        value = content.__bytes__()
        if isinstance(value, byte_cls):
            return value

    value = content.native
    if isinstance(value, byte_cls):
        return value

    raise CMSVerificationError('The signed content must be a byte string')


def _encapsulated_content_bytes(signed_data):
    return _content_bytes(signed_data['encap_content_info']['content'])


def _crypto_hash_algorithm(hash_algo):
    from cryptography.hazmat.primitives import hashes

    hash_classes = {
        'md5': getattr(hashes, 'MD5', None),
        'sha1': getattr(hashes, 'SHA1', None),
        'sha224': getattr(hashes, 'SHA224', None),
        'sha256': getattr(hashes, 'SHA256', None),
        'sha384': getattr(hashes, 'SHA384', None),
        'sha512': getattr(hashes, 'SHA512', None),
        'sha512_224': getattr(hashes, 'SHA512_224', None),
        'sha512_256': getattr(hashes, 'SHA512_256', None),
        'sha3_224': getattr(hashes, 'SHA3_224', None),
        'sha3_256': getattr(hashes, 'SHA3_256', None),
        'sha3_384': getattr(hashes, 'SHA3_384', None),
        'sha3_512': getattr(hashes, 'SHA3_512', None),
    }
    hash_class = hash_classes.get(hash_algo.replace('-', '_').lower())
    if hash_class is None:
        raise CMSVerificationError('Unsupported digest algorithm %s' % hash_algo)
    return hash_class()


def _rsa_pss_padding(algorithm):
    from cryptography.hazmat.primitives.asymmetric import padding

    parameters = algorithm['parameters']
    if _is_void(parameters):
        raise CMSVerificationError('RSA-PSS parameters are missing')

    hash_algo = parameters['hash_algorithm']['algorithm'].native
    mgf_algorithm = parameters['mask_gen_algorithm']
    if mgf_algorithm['algorithm'].native != 'mgf1':
        raise CMSVerificationError('Unsupported RSA-PSS mask generation algorithm')
    mgf_hash_algo = mgf_algorithm['parameters']['algorithm'].native
    salt_length = parameters['salt_length'].native
    if parameters['trailer_field'].native != 'trailer_field_bc':
        raise CMSVerificationError('Unsupported RSA-PSS trailer field')

    pss = padding.PSS(
        mgf=padding.MGF1(_crypto_hash_algorithm(mgf_hash_algo)),
        salt_length=salt_length
    )
    return pss, hash_algo


def _signature_hash_name(signature_algorithm, digest_algo):
    signature_algo = signature_algorithm.signature_algo
    if signature_algo in ('ed25519', 'ed448'):
        return None
    if signature_algo == 'rsassa_pss':
        _, hash_algo = _rsa_pss_padding(signature_algorithm)
        return hash_algo

    try:
        return signature_algorithm.hash_algo
    except ValueError:
        return digest_algo


def _verify_signature(public_key, signature, data, signature_algorithm, digest_algo):
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, padding, rsa

    signature_algo = signature_algorithm.signature_algo
    hash_algo = _signature_hash_name(signature_algorithm, digest_algo)
    if hash_algo is not None and hash_algo != digest_algo:
        raise CMSVerificationError(
            'Signature digest algorithm %s does not match SignerInfo digest algorithm %s' %
            (hash_algo, digest_algo)
        )

    try:
        if signature_algo in ('rsassa_pkcs1v15', 'rsassa_pss'):
            if not isinstance(public_key, rsa.RSAPublicKey):
                raise CMSVerificationError('CMS signature algorithm requires an RSA public key')
            hash_algorithm = _crypto_hash_algorithm(hash_algo)
            if signature_algo == 'rsassa_pss':
                pss, _ = _rsa_pss_padding(signature_algorithm)
                public_key.verify(signature, data, pss, hash_algorithm)
            else:
                public_key.verify(signature, data, padding.PKCS1v15(), hash_algorithm)

        elif signature_algo == 'ecdsa':
            if not isinstance(public_key, ec.EllipticCurvePublicKey):
                raise CMSVerificationError('CMS signature algorithm requires an EC public key')
            public_key.verify(signature, data, ec.ECDSA(_crypto_hash_algorithm(hash_algo)))

        elif signature_algo == 'dsa':
            if not isinstance(public_key, dsa.DSAPublicKey):
                raise CMSVerificationError('CMS signature algorithm requires a DSA public key')
            public_key.verify(signature, data, _crypto_hash_algorithm(hash_algo))

        elif signature_algo == 'ed25519':
            if not isinstance(public_key, ed25519.Ed25519PublicKey):
                raise CMSVerificationError('CMS signature algorithm requires an Ed25519 public key')
            public_key.verify(signature, data)

        elif signature_algo == 'ed448':
            if not isinstance(public_key, ed448.Ed448PublicKey):
                raise CMSVerificationError('CMS signature algorithm requires an Ed448 public key')
            public_key.verify(signature, data)

        else:
            raise CMSVerificationError('Unsupported CMS signature algorithm %s' % signature_algo)

    except InvalidSignature:
        raise CMSVerificationError('CMS signature is invalid')
    except (TypeError, ValueError) as e:
        raise CMSVerificationError('Unable to verify CMS signature: %s' % e)


def _verify_cms_algorithm_protection(signer_info):
    attributes = signer_info['signed_attrs']
    protections = _attribute_values(attributes, 'cms_algorithm_protection')
    if len(protections) > 1:
        raise CMSVerificationError('SignerInfo contains multiple CMS algorithm protection attributes')
    if not protections:
        return

    protection = protections[0]
    digest_algorithm = protection['digest_algorithm']
    if digest_algorithm['algorithm'].dotted != signer_info['digest_algorithm']['algorithm'].dotted:
        raise CMSVerificationError('CMS algorithm protection digest algorithm does not match SignerInfo')

    protected_signature = protection['signature_algorithm']
    protected_mac = protection['mac_algorithm']
    if _is_void(protected_signature):
        if _is_void(protected_mac):
            raise CMSVerificationError('CMS algorithm protection contains neither a signature nor MAC algorithm')
        raise CMSVerificationError('CMS algorithm protection MAC algorithm is not valid for SignedData')

    if not _is_void(protected_mac):
        raise CMSVerificationError('CMS algorithm protection contains both signature and MAC algorithms')

    if protected_signature.dump() != signer_info['signature_algorithm'].dump():
        raise CMSVerificationError('CMS algorithm protection signature algorithm does not match SignerInfo')


def _verify_signer_crypto(signer_info, certificate, content, expected_content_type=None):
    digest_algo = signer_info['digest_algorithm']['algorithm'].native
    signed_attrs = signer_info['signed_attrs']

    if _is_void(signed_attrs):
        signed_data = content
    else:
        content_type_values = _attribute_values(signed_attrs, 'content_type')
        if len(content_type_values) != 1:
            raise CMSVerificationError('SignerInfo must contain exactly one content type signed attribute')
        if expected_content_type is not None and content_type_values[0].native != expected_content_type:
            raise CMSVerificationError('Signed attribute content type does not match encapsulated content')

        message_digest_values = _attribute_values(signed_attrs, 'message_digest')
        if len(message_digest_values) != 1:
            raise CMSVerificationError('SignerInfo must contain exactly one message digest signed attribute')

        expected_digest = message_digest_values[0].native
        actual_digest = _digest_bytes(digest_algo, content)
        if not _constant_time_equals(actual_digest, expected_digest):
            raise CMSVerificationError('CMS message digest does not match the signed content')

        signed_data = _signed_attributes_der(signed_attrs)

    _verify_cms_algorithm_protection(signer_info)
    _verify_signature(
        certificate.crypto.public_key(),
        signer_info['signature'].native,
        signed_data,
        signer_info['signature_algorithm'],
        digest_algo
    )


def _normalize_verification_time(value):
    if value is None:
        return datetime.now(timezone.utc)

    if isinstance(value, int_types):
        return datetime.fromtimestamp(value, timezone.utc)

    if not isinstance(value, datetime):
        raise CMSVerificationError('verification_time must be a datetime or POSIX timestamp')

    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _certificate_validity(certificate):
    try:
        return certificate.not_valid_before_utc, certificate.not_valid_after_utc
    except AttributeError:
        not_before = certificate.not_valid_before
        not_after = certificate.not_valid_after
        if not_before.tzinfo is None:
            not_before = not_before.replace(tzinfo=timezone.utc)
        if not_after.tzinfo is None:
            not_after = not_after.replace(tzinfo=timezone.utc)
        return not_before, not_after


def _check_certificate_time(certificate, verification_time):
    not_before, not_after = _certificate_validity(certificate.crypto)
    if verification_time < not_before:
        raise CMSVerificationError('Certificate is not valid yet')
    if verification_time > not_after:
        raise CMSVerificationError('Certificate has expired')


def _check_leaf_key_usage(certificate):
    key_usage = certificate.asn1.key_usage_value
    if key_usage is None:
        return
    key_usage = key_usage.native
    if 'digital_signature' not in key_usage and 'non_repudiation' not in key_usage:
        raise CMSVerificationError('Signer certificate is not valid for digital signatures')


def _check_issuer_usage(certificate, is_anchor):
    basic_constraints = certificate.asn1.basic_constraints_value
    if basic_constraints is None:
        if not is_anchor:
            raise CMSVerificationError('Certificate issuer is not a CA')
    elif not basic_constraints['ca'].native:
        raise CMSVerificationError('Certificate issuer is not a CA')

    key_usage = certificate.asn1.key_usage_value
    if key_usage is not None and 'key_cert_sign' not in key_usage.native:
        raise CMSVerificationError('Certificate issuer is not valid for certificate signing')


def _certificate_issued_by(certificate, issuer):
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, padding, rsa

    public_key = issuer.crypto.public_key()
    signature = certificate.crypto.signature
    tbs_certificate = certificate.crypto.tbs_certificate_bytes
    hash_algorithm = certificate.crypto.signature_hash_algorithm
    parameters = getattr(certificate.crypto, 'signature_algorithm_parameters', None)

    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            if isinstance(parameters, padding.PSS):
                public_key.verify(signature, tbs_certificate, parameters, hash_algorithm)
            elif certificate.asn1['signature_algorithm']['algorithm'].native == 'rsassa_pss':
                pss, _ = _rsa_pss_padding(certificate.asn1['signature_algorithm'])
                public_key.verify(signature, tbs_certificate, pss, hash_algorithm)
            else:
                public_key.verify(signature, tbs_certificate, padding.PKCS1v15(), hash_algorithm)

        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            if not isinstance(parameters, ec.ECDSA):
                parameters = ec.ECDSA(hash_algorithm)
            public_key.verify(signature, tbs_certificate, parameters)

        elif isinstance(public_key, dsa.DSAPublicKey):
            public_key.verify(signature, tbs_certificate, hash_algorithm)

        elif isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            public_key.verify(signature, tbs_certificate)

        else:
            raise CMSVerificationError('Unsupported certificate public key type')

    except InvalidSignature:
        raise CMSVerificationError('Certificate signature is invalid')
    except (TypeError, ValueError) as e:
        raise CMSVerificationError('Unable to verify certificate signature: %s' % e)


def _check_path_lengths(chain):
    for index, certificate in enumerate(chain[1:], 1):
        basic_constraints = certificate.asn1.basic_constraints_value
        if basic_constraints is None:
            continue
        path_length = basic_constraints['path_len_constraint'].native
        if path_length is None:
            continue
        subordinate_cas = 0
        for subordinate in chain[1:index]:
            if subordinate.asn1.ca:
                subordinate_cas += 1
        if subordinate_cas > path_length:
            raise CMSVerificationError('Certificate chain exceeds a CA path length constraint')


def _verify_certificate_chain(certificate, candidates, trust_store, verification_time):
    anchor_required = trust_store is not None
    anchors = _load_certificates(trust_store)
    if anchor_required and not anchors:
        raise CMSVerificationError('No trust anchors were provided')

    all_candidates = _load_certificates(list(candidates) + anchors)
    anchor_ders = set(anchor.der for anchor in anchors)

    _check_certificate_time(certificate, verification_time)
    _check_leaf_key_usage(certificate)

    if not anchor_required:
        return [certificate.asn1]

    chain = [certificate]
    if certificate.der in anchor_ders:
        return [item.asn1 for item in chain]

    while len(chain) <= 20:
        current = chain[-1]
        issuer = None
        for candidate in all_candidates:
            if candidate.der == current.der:
                continue
            if candidate.crypto.subject != current.crypto.issuer:
                continue
            try:
                _certificate_issued_by(current, candidate)
                _check_certificate_time(candidate, verification_time)
                _check_issuer_usage(candidate, candidate.der in anchor_ders)
            except CMSVerificationError:
                continue
            issuer = candidate
            break

        if issuer is None:
            raise CMSVerificationError('Unable to build a certificate chain to a trusted root')

        chain.append(issuer)

        if issuer.der in anchor_ders:
            _check_path_lengths(chain)
            return [item.asn1 for item in chain]

    raise CMSVerificationError('Certificate chain is too long')


def _verify_timestamp_token(signer_info, token, trust_store, extra_certs):
    if token['content_type'].native != 'signed_data':
        raise CMSVerificationError('Timestamp token does not contain SignedData')

    from . import tsp

    timestamp_signed_data = token['content']
    encap_content_info = timestamp_signed_data['encap_content_info']
    if encap_content_info['content_type'].native != 'tst_info':
        raise CMSVerificationError('Timestamp token does not contain TSTInfo')

    timestamp_content = _content_bytes(encap_content_info['content'])
    tst_info = encap_content_info['content'].parsed
    if not isinstance(tst_info, tsp.TSTInfo):
        tst_info = tsp.TSTInfo.load(timestamp_content)

    if tst_info['version'].native != 'v1':
        raise CMSVerificationError('Unsupported TSTInfo version')

    gen_time = _normalize_verification_time(tst_info['gen_time'].native)
    timestamp_result = _verify_signed_data(
        timestamp_signed_data,
        timestamp_content,
        trust_store,
        extra_certs,
        gen_time,
        False,
        False,
        None,
        False
    )

    if not timestamp_result.signers:
        raise CMSVerificationError('Timestamp token does not contain a signer')

    message_imprint = tst_info['message_imprint']
    imprint_algorithm = message_imprint['hash_algorithm']['algorithm'].native
    expected_imprint = message_imprint['hashed_message'].native
    actual_imprint = _digest_bytes(imprint_algorithm, signer_info['signature'].native)
    if not _constant_time_equals(actual_imprint, expected_imprint):
        raise CMSVerificationError('Timestamp message imprint does not match the SignerInfo signature')

    timestamp_signer = timestamp_result.signers[0]
    return CMSTimestampVerificationResult(
        gen_time,
        tst_info['policy'].dotted,
        tst_info['serial_number'].native,
        tst_info['tsa'].native,
        tst_info,
        timestamp_signed_data,
        timestamp_signer.certificate,
        timestamp_signer.certificate_chain
    )


def _verify_signed_data(signed_data, content, trust_store, extra_certs, verification_time,
                        require_timestamp, verify_timestamp, timestamp_trust_store,
                        use_timestamp_for_validity):
    if content is None:
        content = _encapsulated_content_bytes(signed_data)
    else:
        content = _content_bytes(content)

    anchors = _load_certificates(trust_store)
    candidates = _get_signed_data_certificates(signed_data, extra_certs)
    candidates = _load_certificates(candidates + anchors)

    signer_results = []
    signer_infos = signed_data['signer_infos']
    if len(signer_infos) == 0:
        raise CMSVerificationError('SignedData does not contain any signers')

    for signer_info in signer_infos:
        certificate = _find_signer_certificate(signer_info, candidates)
        expected_content_type = signed_data['encap_content_info']['content_type'].native
        _verify_signer_crypto(signer_info, certificate, content, expected_content_type)

        timestamp = None
        timestamp_values = _attribute_values(signer_info['unsigned_attrs'], 'signature_time_stamp_token')
        if len(timestamp_values) > 1:
            raise CMSVerificationError('SignerInfo contains more than one timestamp token')
        if timestamp_values:
            if verify_timestamp:
                timestamp_anchors = timestamp_trust_store if timestamp_trust_store is not None else trust_store
                timestamp = _verify_timestamp_token(
                    signer_info,
                    timestamp_values[0],
                    timestamp_anchors,
                    extra_certs
                )
        elif require_timestamp:
            raise CMSVerificationError('SignerInfo does not contain a timestamp token')

        if verification_time is not None:
            effective_time = _normalize_verification_time(verification_time)
        elif timestamp is not None and use_timestamp_for_validity:
            effective_time = timestamp.gen_time
        else:
            effective_time = _normalize_verification_time(None)

        chain = _verify_certificate_chain(certificate, candidates, trust_store, effective_time)
        signer_results.append(
            CMSSignerVerificationResult(
                signer_info,
                certificate.asn1,
                chain,
                timestamp,
                effective_time
            )
        )

    return CMSSignedDataVerificationResult(signer_results)


def verify_signed_data(signed_data, content=None, trust_store=None, extra_certs=None,
                       verification_time=None, require_timestamp=False, verify_timestamp=True,
                       timestamp_trust_store=None, use_timestamp_for_validity=True,
                       return_info=False, raise_errors=False, **kwargs):
    """
    Convenience wrapper around SignedData.verify().
    """

    return signed_data.verify(
        content,
        trust_store,
        extra_certs,
        verification_time,
        require_timestamp,
        verify_timestamp,
        timestamp_trust_store,
        use_timestamp_for_validity,
        return_info,
        raise_errors,
        **kwargs
    )


def verify_timestamp_token(token, signer_info, trust_store=None, extra_certs=None):
    """
    Verifies an RFC 3161 timestamp token against the signature of a SignerInfo.

    :param token:
        A cms.ContentInfo object containing SignedData with TSTInfo

    :param signer_info:
        The cms.SignerInfo whose signature is covered by the timestamp

    :raises:
        CMSVerificationError - when the timestamp is invalid

    :return:
        A CMSTimestampVerificationResult object
    """

    return _verify_timestamp_token(signer_info, token, trust_store, extra_certs)


def verify_certificate_chain(certificate, trust_store, intermediates=None,
                             verification_time=None):
    """
    Builds and verifies a certificate chain.

    :param certificate:
        The end-entity certificate

    :param trust_store:
        A certificate or iterable of trust anchors

    :param intermediates:
        None, or a certificate or iterable of intermediate certificates

    :param verification_time:
        None, a datetime or POSIX timestamp for validity checking

    :raises:
        CMSVerificationError - when the chain can not be verified

    :return:
        A list of asn1crypto.x509.Certificate objects, starting with certificate
    """

    leaf = _load_certificate(certificate)
    candidates = [leaf] + _load_certificates(intermediates)
    effective_time = _normalize_verification_time(verification_time)
    return _verify_certificate_chain(leaf, candidates, trust_store, effective_time)
