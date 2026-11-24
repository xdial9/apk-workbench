"""Legacy security package placeholder (OpenPGP verifier retired with F-Droid removal).

Download integrity verification lives in ``apkworkbench.acquisition.verification``
and APK certificate/signing-scheme extraction lives in
``apkworkbench.analysis.surface.identity``. Full cryptographic APK signature
verification (v1 JAR/PKCS#7 and v2/v3 Merkle + asymmetric signature checks)
is not implemented here because it requires ``cryptography`` or ``apksigner``.
"""
