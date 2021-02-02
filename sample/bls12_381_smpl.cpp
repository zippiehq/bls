#include <bls/bls384_256.h>
#include <string.h>
#include <stdio.h>

int main()
{
	// BLS_DLL_API mclSize blsSignatureSerialize(void *buf, mclSize maxBufSize, const blsSignature *sig);

	blsSecretKey sec;
	blsSecretKey blinding;
	blsPublicKey pub;
	blsSignature sig, sig_blinded, sig_unblinded;
	const char *msg = "abc";
	const size_t msgSize = strlen(msg);
	int ret = blsInit(MCL_BLS12_381, MCLBN_COMPILED_TIME_VAR);
	if (ret) {
		printf("err %d\n", ret);
		return 1;
	}
	blsSecretKeySetByCSPRNG(&sec);
	blsSecretKeySetByCSPRNG(&blinding);
	blsGetPublicKey(&pub, &sec);

	blsSign(&sig_blinded, &blinding, msg, msgSize);
	blsBlindSignatureSign(&sig_blinded, &sig, &sec, 0);
	blsBlindSignatureSign(&sig, &sig_unblinded, &blinding, 1);
	// BLS_DLL_API int blsVerify(const blsSignature *sig, const blsPublicKey *pub, const void *m, mclSize size);
	printf("%i\n", blsVerify(&sig_unblinded, &pub, msg, msgSize));

	// BLS_DLL_API void blsBlindSignatureSign(blsSignature *orig_sig, blsSignature *sig, const blsSecretKey *sec, int inverse) {
}
