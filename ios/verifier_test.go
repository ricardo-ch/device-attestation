package ios

import (
	"context"
	"crypto/x509"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewVerifier_Validation(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid config",
			config: Config{
				BundleIDs: []string{"com.example.app"},
				TeamID:    "TEAM123456",
			},
			wantErr: false,
		},
		{
			name: "missing bundle IDs",
			config: Config{
				BundleIDs: []string{},
				TeamID:    "TEAM123456",
			},
			wantErr: true,
			errMsg:  "at least one bundle ID is required",
		},
		{
			name: "missing team ID",
			config: Config{
				BundleIDs: []string{"com.example.app"},
				TeamID:    "",
			},
			wantErr: true,
			errMsg:  "team ID is required",
		},
		{
			name: "multiple bundle IDs",
			config: Config{
				BundleIDs: []string{"com.example.app", "com.example.app.dev"},
				TeamID:    "TEAM123456",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := NewVerifier(tt.config)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
				assert.Nil(t, v)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, v)
			}
		})
	}
}

func TestVerifier_VerifyAttestation_InvalidBundleID(t *testing.T) {
	v, err := NewVerifier(Config{
		BundleIDs: []string{"com.example.app"},
		TeamID:    "TEAM123456",
	})
	require.NoError(t, err)

	_, err = v.VerifyAttestation(context.Background(), &AttestationRequest{
		Attestation: "dGVzdA==",
		Challenge:   "test-challenge",
		KeyID:       "test-key-id",
		BundleID:    "com.other.app",
	})
	assert.ErrorIs(t, err, ErrInvalidBundleID)
}

func TestVerifier_VerifyAttestation_MissingKeyID(t *testing.T) {
	v, err := NewVerifier(Config{
		BundleIDs: []string{"com.example.app"},
		TeamID:    "TEAM123456",
	})
	require.NoError(t, err)

	_, err = v.VerifyAttestation(context.Background(), &AttestationRequest{
		Attestation: "dGVzdA==",
		Challenge:   "test-challenge",
		KeyID:       "",
		BundleID:    "com.example.app",
	})
	assert.ErrorIs(t, err, ErrInvalidKeyID)
}

func TestVerifier_VerifyAttestation_InvalidBase64(t *testing.T) {
	v, err := NewVerifier(Config{
		BundleIDs: []string{"com.example.app"},
		TeamID:    "TEAM123456",
	})
	require.NoError(t, err)

	_, err = v.VerifyAttestation(context.Background(), &AttestationRequest{
		Attestation: "not-valid-base64!!!",
		Challenge:   "test-challenge",
		KeyID:       "test-key-id",
		BundleID:    "com.example.app",
	})
	assert.ErrorIs(t, err, ErrInvalidAttestation)
}

func TestVerifier_VerifyAssertion_NoKeyStore(t *testing.T) {
	v, err := NewVerifier(Config{
		BundleIDs: []string{"com.example.app"},
		TeamID:    "TEAM123456",
	})
	require.NoError(t, err)

	_, err = v.VerifyAssertion(context.Background(), &AssertionRequest{
		Assertion:  "dGVzdA==",
		ClientData: []byte("test"),
		KeyID:      "test-key-id",
		BundleID:   "com.example.app",
	})
	assert.ErrorIs(t, err, ErrKeyStoreRequired)
}

func TestVerifier_VerifyAssertion_KeyNotFound(t *testing.T) {
	keyStore := NewMemoryKeyStore()
	v, err := NewVerifier(Config{
		BundleIDs: []string{"com.example.app"},
		TeamID:    "TEAM123456",
		KeyStore:  keyStore,
	})
	require.NoError(t, err)

	_, err = v.VerifyAssertion(context.Background(), &AssertionRequest{
		Assertion:  "dGVzdA==",
		ClientData: []byte("test"),
		KeyID:      "nonexistent-key",
		BundleID:   "com.example.app",
	})
	assert.ErrorIs(t, err, ErrKeyNotFound)
}

func TestVerifier_DefaultTimeout(t *testing.T) {
	v, err := NewVerifier(Config{
		BundleIDs: []string{"com.example.app"},
		TeamID:    "TEAM123456",
	})
	require.NoError(t, err)
	assert.Equal(t, 5*time.Minute, v.timeout)
}

func TestVerifier_CustomTimeout(t *testing.T) {
	v, err := NewVerifier(Config{
		BundleIDs:        []string{"com.example.app"},
		TeamID:           "TEAM123456",
		ChallengeTimeout: 10 * time.Minute,
	})
	require.NoError(t, err)
	assert.Equal(t, 10*time.Minute, v.timeout)
}

func TestRicardoVerifier(t *testing.T) {
	store := NewMemoryKeyStore()
	attestation := `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`
	keyID := "D++z1XCwnozS1QV79R28ApfUDde0xZo3HQg7SP4rt4U="
	assertion := `omlzaWduYXR1cmVYRjBEAiAEf9zhW+h7kJqvq8h6TT3Qi/2wvQVTYuA4n6SZr/QCxgIgffvV5BhGl+YFeACP2qS7hS1Z2vd4RjynmOHaSvifp2NxYXV0aGVudGljYXRvckRhdGFYZt1jdq+PcojBSuLzpB4xgw+g2DIrxiJTXANYQ1mU8QX9wAAAAAGid2FwcGxlX2J1bmRsZV92ZXJzaW9uXzAxZDEzMTR4HGFwcGxlX3ZhbGlkYXRpb25fY2F0ZWdvcnlfMDFEAwAAAA==`
	clientData := `ABCDE`
	bundleID := "swiss.ricardo.iphone.beta"
	teamID := "J4Y28BA299"
	challenge := "3Eo1sQZURkLbdhqclSvuWL5J3_9JxCjOfvafjPVWnRE"
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM([]byte(appleAppAttestRootCA))
	// Also add the legacy root CA (same key, different DN encoding)
	// Some intermediate certificates may chain to the older version
	pool.AppendCertsFromPEM([]byte(appleAppAttestRootCALegacy))

	verif := Verifier{
		bundleIDSet:                 map[string]struct{}{bundleID: {}},
		teamID:                      teamID,
		rootCertPool:                pool,
		timeout:                     5 * time.Minute,
		keyStore:                    store,
		production:                  false,
		skipCertificateVerification: false,
	}

	attReq := AttestationRequest{
		Attestation: attestation,
		Challenge:   challenge,
		KeyID:       keyID,
		BundleID:    bundleID,
	}

	_, err := verif.VerifyAttestation(context.Background(), &attReq)
	assert.NoError(t, err)

	req := AssertionRequest{
		Assertion:  assertion,
		ClientData: []byte(clientData),
		KeyID:      keyID,
		BundleID:   "swiss.ricardo.iphone.beta",
	}
	_, err = verif.VerifyAssertion(context.Background(), &req)
	assert.NoError(t, err)
}
