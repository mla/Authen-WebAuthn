use Test::More;
use Crypt::PK::ECC;
use CBOR::XS;
use Digest::SHA qw(sha256);
use MIME::Base64 qw(encode_base64url);
use strict;

use Authen::WebAuthn;
use Authen::WebAuthn::Test;

# Attestation signed with certificates from the test PKI in t/pki (see
# t/pki/generate), through the simulator

# The test PKI is valid from 2026-11-21 for 100 years
$Authen::WebAuthn::SSLeayChainVerifier::verification_time = 1796083200;

sub pem {
    my ($name) = @_;
    open my $fh, '<', "t/pki/$name.pem" or die "t/pki/$name.pem: $!";
    local $/;
    return <$fh>;
}

my $rp = Authen::WebAuthn->new(
    origin => "http://auth.example.com",
    rp_id  => "auth.example.com",
);

my $credential_key = Crypt::PK::ECC->new;
$credential_key->generate_key("secp256r1");

sub authenticator {
    my (%args) = @_;
    my $certificate = delete $args{certificate};
    return Authen::WebAuthn::Test->new(
        origin             => "http://auth.example.com",
        rp_id              => "auth.example.com",
        credential_id      => "credential",
        aaguid             => "00000000-0000-0000-0000-000000000000",
        key                => $credential_key->export_key_pem("private"),
        attestation_format => "packed",
        (
            $certificate
            ? (
                attestation_key          => pem("$certificate-key"),
                attestation_certificates => [ pem($certificate) ],
              )
            : ()
        ),
        %args,
    );
}

sub register {
    my ( $authenticator, %options ) = @_;
    my $credential = $authenticator->get_credential_response(
        { request => { challenge => "abc" } } );
    return scalar eval {
        $rp->validate_registration(
            challenge_b64        => "abc",
            client_data_json_b64 =>
              encode_base64url( $credential->{response}->{clientDataJSON} ),
            attestation_object_b64 => encode_base64url(
                $credential->{response}->{attestationObject}
            ),
            trust_anchors => [ pem("root") ],
            %options,
        );
    };
}

sub refused {
    my ( $result, $message, $name ) = @_;
    ok( !$result, $name );
    like( $@, $message, "... with the expected message" );
}

subtest "Packed attestation, each key type" => sub {
    for my $certificate (qw(packed-p256 packed-rsa) ) {
        my $reg = register( authenticator( certificate => $certificate ) );
        ok( $reg, $certificate ) or diag($@);
        is( $reg && $reg->{attestation_result}->{type},
            "Basic", "... as Basic attestation" );
    }
};

subtest "Certificate chains" => sub {
    my $chained = authenticator(
        attestation_key          => pem("packed-chained-key"),
        attestation_certificates =>
          [ pem("packed-chained"), pem("intermediate") ],
    );
    ok( register($chained), "Through an intermediate" ) or diag($@);

    $chained->attestation_certificates( [ pem("packed-chained") ] );
    refused( register($chained), qr/Could not verify X.509 chain/,
        "Without the intermediate" );

    my $direct = authenticator( certificate => "packed-p256" );
    ok( register( $direct, trust_anchors => [ pem("packed-p256") ] ),
        "Trusting the attestation certificate itself" );
    refused(
        register( $direct, trust_anchors => [ pem("intermediate") ] ),
        qr/Could not verify X.509 chain/,
        "Trusting another authority"
    );
};

subtest "AAGUID extension" => sub {
    my $aaguid = "01020304-0506-0708-090a-0b0c0d0e0f10";
    my $reg    = register(
        authenticator( certificate => "packed-aaguid", aaguid => $aaguid ) );
    ok( $reg, "Matching the authenticator data" ) or diag($@);
    is( $reg && $reg->{attestation_result}->{aaguid},
        $aaguid, "... and reported" );

    refused(
        register( authenticator( certificate => "packed-aaguid" ) ),
        qr/AAGUID from certificate \(0102030405060708090A0B0C0D0E0F10\) does not match/,
        "Not matching"
    );
};

# validate_registration checks trust anchors before they get here, but the
# chain verifier is also called directly
subtest "Chain verifier input that does not parse" => sub {
    my $der = Crypt::OpenSSL::X509->new_from_string( pem("packed-p256") )
      ->as_string(Crypt::OpenSSL::X509::FORMAT_ASN1);
    for my $case (
        [ [ pem("root") ], "garbage", "A certificate" ],
        [ [ pem("root"), "garbage" ], $der, "The second of two anchors" ],
      )
    {
        my ( $anchors, $leaf, $name ) = @$case;
        my $result = eval {
            Authen::WebAuthn::SSLeayChainVerifier::verify_chain( $anchors,
                $leaf, [] );
        };
        ok( !( $result && $result->{result} ), "$name is refused" );
        like(
            $@ || $result->{message},
            qr/Could not parse certificate/,
            "... with the expected message"
        );
        is( Net::SSLeay::ERR_peek_error(), 0,
            "... leaving OpenSSL's error queue empty" );
    }
};

subtest "Certificate requirements" => sub {
    my %expected = (
        "bad-v1"    => qr/Invalid certificate version/,
        "bad-no-c"  => qr/Missing subject C/,
        "bad-no-o"  => qr/Missing subject O/,
        "bad-no-cn" => qr/Missing subject CN/,
        "bad-no-ou" => qr/Missing subject OU/,
        "bad-ou"    => qr/Unexpected OU/,
        "bad-ca"    => qr/Basic Constraints CA is true/,
        "bad-no-bc" => qr/Missing Basic Constraints extension/,
    );
    for my $certificate ( sort keys %expected ) {
        refused( register( authenticator( certificate => $certificate ) ),
            $expected{$certificate}, $certificate );
    }
};

subtest "Packed attestation signatures" => sub {
    refused(
        register(
            authenticator(
                attestation_key          => pem("bad-ou-key"),
                attestation_certificates => [ pem("packed-p256") ],
            )
        ),
        qr/Invalid attestation signature/,
        "Signed with another key"
    );
    refused(
        register(
            authenticator(
                attestation_key          => pem("packed-p256-key"),
                attestation_certificates => [ pem("packed-rsa") ],
            )
        ),
        qr/Cannot get signature validator for attestation/,
        "A certificate key of another type than the algorithm"
    );

    # ES256 is ECDSA on P-256: the same statement, named ES256 and signed
    # with SHA-256 by the certificate's P-384 key
    my $credential = authenticator( certificate => "packed-p384" )
      ->get_credential_response( { request => { challenge => "abc" } } );
    my $object =
      CBOR::XS::decode_cbor( $credential->{response}->{attestationObject} );
    my $p384 = Crypt::PK::ECC->new( \pem("packed-p384-key") );
    $object->{attStmt}->{alg} = -7;
    $object->{attStmt}->{sig} = $p384->sign_message(
        $object->{authData}
          . sha256( $credential->{response}->{clientDataJSON} ),
        "SHA256"
    );
    my $result = eval {
        $rp->validate_registration(
            challenge_b64        => "abc",
            client_data_json_b64 =>
              encode_base64url( $credential->{response}->{clientDataJSON} ),
            attestation_object_b64 => encode_base64url(
                Authen::WebAuthn::Test::_canonical_cbor($object)
            ),
            trust_anchors => [ pem("root") ],
        );
    };
    refused(
        $result,
        qr/Curve secp384r1 cannot be used with algorithm -7/,
        "ES256 signed by a P-384 certificate key"
    );
};

subtest "FIDO U2F attestation" => sub {
    my $reg = register(
        authenticator(
            certificate        => "packed-p256",
            attestation_format => "fido-u2f"
        )
    );
    ok( $reg, "With a P-256 certificate" ) or diag($@);
    is( $reg && $reg->{attestation_result}->{type}, "Basic", "... as Basic" );

    refused(
        register(
            authenticator(
                certificate        => "packed-p384",
                attestation_format => "fido-u2f"
            )
        ),
        qr/Invalid attestation certificate curve name: secp384r1/,
        "With a P-384 certificate"
    );
    refused(
        register(
            authenticator(
                certificate        => "packed-rsa",
                attestation_format => "fido-u2f"
            )
        ),
        qr/Could not extract ECC key from attestation certificate/,
        "With an RSA certificate"
    );
};

done_testing();
