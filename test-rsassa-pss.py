import json
import binascii
import subprocess
import hashlib
import sys, getopt, os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import cryptography.hazmat.backends

def load_rsa_wp_vectors(tc_json):
        with open(tc_json) as tc:
                testcases = json.load(tc)

        return testcases

def do_cmd(command):
        return subprocess.run(command.split())

def openssl_gen_cert_with_pem(pem_name, rsa_bits, hash_algo, slen):
        # generate a DER certificate with force_pubkey instead of the embedded one.

        out_fname = "scratch.crt"
        do_cmd("openssl genrsa -out rootCA.key {}".format(rsa_bits))
        do_cmd("openssl req -x509 -new -nodes -key rootCA.key -{} -days 1024 -out rootCA.crt -config x509.genkey".format(hash_algo))
        do_cmd("openssl genrsa -out scratch.key {}".format(rsa_bits))
        do_cmd("openssl req -new -{} -config x509.genkey -key scratch.key -out scratch.csr".format(hash_algo))
        do_cmd("openssl x509 -req -in scratch.csr -CA rootCA.crt -CAkey rootCA.key -CAcreateserial -extensions myexts -extfile x509.genkey -out {} -outform der -days 500 -{} -force_pubkey {} -sigopt rsa_padding_mode:pss -{} -sigopt rsa_mgf1_md:{} -sigopt rsa_pss_saltlen:{}".format(out_fname, hash_algo, pem_name, hash_algo, hash_algo, slen))
        return out_fname

def keyctl_pkey_add(cert_der):
        return subprocess.run("keyctl padd asymmetric test @u".split(), input=bytes(cert_der), stdout = subprocess.PIPE)

def keyctl_pkey_verify(kv, hash_algo, dat_bin, sig_bin, salt_len):
        ver_cmd =  'keyctl pkey_verify {} "0" {} {} "enc=pss hash={} saltlen={} mgfhash={}"'.format(kv, dat_bin, sig_bin, hash_algo, salt_len, hash_algo)
        return subprocess.run(ver_cmd, shell=True)

def keyctl_load_cert(cert_file):
        with open(cert_file, "rb") as cert:
                cert_der = cert.read()

        kv = keyctl_pkey_add(cert_der)
        return str(kv.stdout.strip().decode("ascii"))

def openssl_pkey_verify(pubkey, signature, hash_algo, slen, data):
        ver_cmd = "openssl dgst -verify {} -sigopt rsa_padding_mode:pss  -sigopt rsa_pss_saltlen:{} -{} -signature {} {}".format(
                pubkey, slen, hash_algo, signature, data
        )
        return subprocess.run(ver_cmd, shell=True, stdout = subprocess.PIPE, stderr=subprocess.PIPE)

def dump_file(ss, fname, flag):
        with open(fname, flag) as ff:
                ff.write(ss)

def dump_bin_file(ss, fname):
        dump_file(binascii.unhexlify(ss), fname, "wb")

def dump_bin_files(vv):
        for v in vv:
                dump_bin_file(v["cont"], v["name"])

def hash_msg(msg, hash_algo):
        data_hash = binascii.unhexlify(msg)

        if (hash_algo == "sha1"):
                data_hash = hashlib.sha1(data_hash).hexdigest()
        elif (hash_algo == "sha256"):
                data_hash = hashlib.sha256(data_hash).hexdigest()
        elif (hash_algo == "sha512"):
                data_hash = hashlib.sha512(data_hash).hexdigest()
        elif (hash_algo == "sha384"):
                data_hash = hashlib.sha384(data_hash).hexdigest()
        elif (hash_algo == "sha224"):
                data_hash = hashlib.sha224(data_hash).hexdigest()

        return data_hash

def check_verify(c, expected):
        if c.returncode and expected == True:
                return -1 # false reject
        elif c.returncode == 0 and expected != True:
                return -2 # false accept
        elif c.returncode == 0 and expected == True:
                return 0 # ok
        elif c.returncode != 0 and expected != True:
                return 0 # ok

def run_pkey_verify_test(pubkey_pem, mod_len, hash_algo, salt_len, sig, msg, data_hash):
        pem_name = "key-pss.pem"
        with open(pem_name, "wb") as f:
                f.write(pubkey_pem)

        cert_der_f = openssl_gen_cert_with_pem(pem_name, mod_len, hash_algo, salt_len)
        kv = keyctl_load_cert(cert_der_f)
        dump_bin_files([{"cont" : sig, "name" : "sig.bin"},
                        {"cont" : msg, "name" : "data.txt"},
                        {"cont" : data_hash, "name" : "data.{}.bin".format(hash_algo)}])
        return keyctl_pkey_verify(kv, hash_algo, "data.{}.bin".format(hash_algo), "sig.bin", salt_len)

def run_wp_tests(tc_json, start=0, end=-1):
        testcases = load_rsa_wp_vectors(tc_json)

        pubkey_pem = testcases["testGroups"][0]["keyPem"].encode("ascii")
        mod_len = testcases["testGroups"][0]["keysize"]
        hash_algo = { "SHA-1" : "sha1", "SHA-256" : "sha256", "SHA-512" : "sha512" }
        hash_algo = hash_algo[testcases["testGroups"][0]["sha"]]
        salt_len = testcases["testGroups"][0]["sLen"]
        i = 0

        for test in testcases["testGroups"][0]["tests"][start:end]:
                expected = (test["result"] == "valid" or test["result"] == "acceptable")

                c = run_pkey_verify_test(pubkey_pem, mod_len, hash_algo, salt_len, test["sig"], test["msg"], hash_msg(test["msg"], hash_algo))
                ret = check_verify(c, expected)
                if (ret < 0):
                        print("tc={} hash_algo={} salt_len={} mod_len={} ret={}".format(test["tcId"], hash_algo, salt_len, mod_len, "false accept" if ret == -2 else "false reject"))
                i += 1

def load_rsa_nist_vectors(vector_data):
    #https://github.com/pyca/cryptography/blob/3.4.x/tests/utils.py#L280
    test_data: typing.Dict[str, typing.Any] = {}
    p = None
    salt_length = None
    data = []

    for line in vector_data:
        line = line.strip()

        # Blank lines and section headers are ignored
        if not line or line.startswith("["):
            continue

        if line.startswith("# Salt len:"):
            salt_length = int(line.split(":")[1].strip())
            continue
        elif line.startswith("#"):
            continue

        # Build our data using a simple Key = Value format
        name, value = [c.strip() for c in line.split("=")]

        if name == "n":
            n = int(value, 16)
        elif name == "e" and p is None:
            e = int(value, 16)
        elif name == "p":
            p = int(value, 16)
        elif name == "q":
            q = int(value, 16)
        elif name == "SHAAlg":
            if p is None:
                test_data = {
                    "modulus": n,
                    "public_exponent": e,
                    "salt_length": salt_length,
                    "algorithm": value,
                    "fail": False,
                }
            else:
                test_data = {"modulus": n, "p": p, "q": q, "algorithm": value}
                if salt_length is not None:
                    test_data["salt_length"] = salt_length
            data.append(test_data)
        elif name == "e" and p is not None:
            test_data["public_exponent"] = int(value, 16)
        elif name == "d":
            test_data["private_exponent"] = int(value, 16)
        elif name == "Result":
            test_data["fail"] = value.startswith("F")
        # For all other tokens we simply want the name, value stored in
        # the dictionary
        else:
            test_data[name.lower()] = value.encode("ascii")

    return data

def infer_nist_saltlen(testcase, mod_len, hash_algo):
        salt_len = 0
        if "salt_length" not in testcase:
                # CAVS 11.1 specifies slen in a different way. Hard code them here.
                # Mod Size 1024 with SHA-1(Salt len: 20); SHA-224(Salt len: 20); SHA-256(Salt len: 20); SHA-384(Salt len: 20); SHA-512(Salt len: 20);; Mod Size 2048 with SHA-1(Salt len: 20); SHA-224(Salt len: 28); SHA-256(Salt len: 32); SHA-384(Salt len: 48); SHA-512(Salt len: 64);; Mod Size 3072 with SHA-1(Salt len: 0); SHA-224(Salt len: 0); SHA-256(Salt len: 0); SHA-384(Salt len: 24); SHA-512(Salt len: 0);
                if mod_len == 3072:
                        salt_len = 24 if hash_algo == "sha384" else 0
                elif mod_len == 1024:
                        salt_len = 20
                elif mod_len == 2048:
                        salt_len = 20 if hash_algo == "sha1" else int(int(hash_algo[3:]) / 8)
        else:
                salt_len = testcase["salt_length"]
        return salt_len

def run_nist_tests(vec_file):
        with open(vec_file, "r") as f:
                v = f.readlines()

        vec_dat = load_rsa_nist_vectors(v)
        i = 0
        for testcase in vec_dat:
                pubkey = rsa.RSAPublicNumbers(e=testcase["public_exponent"], n=testcase["modulus"]).public_key(cryptography.hazmat.backends.default_backend())
                pubkey_pem = pubkey.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)

                mod_len = len(bin(testcase["modulus"])) - 2
                hash_algo = testcase["algorithm"].lower()
                salt_len = infer_nist_saltlen(testcase, mod_len, hash_algo)
                expected = not testcase["fail"]

                c = run_pkey_verify_test(pubkey_pem, mod_len, hash_algo, salt_len, testcase["s"], testcase["msg"], hash_msg(testcase["msg"], hash_algo))
                ret = check_verify(c, expected)
                if (ret < 0):
                        print("tc={} hash_algo={} salt_len={} mod_len={} ret={}".format(i, hash_algo, salt_len, mod_len, "false accept" if ret == -2 else "false reject"))
                i += 1

wycheproof_vectors = [
    "rsa_pss_2048_sha1_mgf1_20_test.json",
    "rsa_pss_2048_sha256_mgf1_0_test.json",
    "rsa_pss_2048_sha256_mgf1_32_test.json",
    "rsa_pss_2048_sha512_256_mgf1_28_test.json",
    "rsa_pss_2048_sha512_256_mgf1_32_test.json",
    "rsa_pss_3072_sha256_mgf1_32_test.json",
    "rsa_pss_4096_sha256_mgf1_32_test.json",
    "rsa_pss_4096_sha512_mgf1_32_test.json",
    "rsa_pss_misc_test.json"
]

nist_vectors = [
        "SigVerPSS_186-1.rsp",
#        "SigVerPSS_186-2.rsp",
        "SigVerPSS_186-3.rsp",
        ]

def main(argv):
        wycheproof_path = None

        try:
                opts, args = getopt.getopt(argv, "w:n:", ["wycheproof_path=", "nist_path="])
        except getopt.GetoptError:
                sys.exit(2)
        for opt, arg in opts:
                if opt in ("-w", "--wycheproof_path="):
                        wycheproof_path = arg
                elif opt in ("-n", "--nist_path="):
                        nist_path = arg

        if wycheproof_path:
                if not os.path.exists(wycheproof_path):
                        print("Path {} not found.".format(wycheproof_path))
                        exit()

                for wp_vec in wycheproof_vectors:
                        p = os.path.join(wycheproof_path, wp_vec)
                        if not os.path.exists(p):
                                print("Skipping vector {}, not found.".format(wp_vec))
                                continue
                        run_wp_tests(p)

        if nist_path:
                if not os.path.exists(nist_path):
                        print("Path {} not found.".format(nist_path))
                        exit()

                for nist_vec in nist_vectors:
                        p = os.path.join(nist_path, nist_vec)
                        if not os.path.exists(p):
                                print("Skipping vector {}, not found.".format(wp_vec))
                                continue
                        run_nist_tests(p)

if __name__ == "__main__":
        main(sys.argv[1:])

